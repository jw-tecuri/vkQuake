#!/usr/bin/env python3
"""Assemble a self-contained, ad-hoc signed vkQuake.app plus DMG and zip.

The Meson build links Homebrew libraries (MoltenVK directly, SDL, codecs).
This script copies every non-system Mach-O dependency into
Contents/Frameworks, rewrites install names so nothing points at
/opt/homebrew or /usr/local, and checks the bundle the CI job relies on.
"""

import argparse
import glob
import json
import os
import plistlib
import shutil
import struct
import subprocess
import sys
import tempfile

FORBIDDEN_PREFIXES = ("/opt/homebrew", "/usr/local", "/opt/local")


def run(cmd, **kwargs):
    print("+", " ".join(cmd), flush=True)
    subprocess.check_call(cmd, **kwargs)


def capture(cmd):
    return subprocess.check_output(cmd, text=True, stderr=subprocess.STDOUT)


def is_macho(path):
    if not os.path.isfile(path) or os.path.islink(path):
        return False
    try:
        out = capture(["file", "-b", path])
    except subprocess.CalledProcessError:
        return False
    return "Mach-O" in out


def fix_linkedit_filesize(path):
    """Shrink a stale __LINKEDIT filesize so install_name_tool will accept the file.

    codesign --remove-signature truncates the code-signature blob but, on some
    Homebrew arm64 binaries (SDL3), leaves LC_SEGMENT_64 filesize pointing past
    EOF. install_name_tool then reports that link-edit information does not
    fill the __LINKEDIT segment.
    """
    with open(path, "rb") as fh:
        data = bytearray(fh.read())
    if len(data) < 32:
        return False
    magic = struct.unpack_from("<I", data, 0)[0]
    if magic != 0xFEEDFACF:  # MH_MAGIC_64
        return False
    ncmds = struct.unpack_from("<I", data, 16)[0]
    offset = 32
    file_size = len(data)
    changed = False
    for _ in range(ncmds):
        if offset + 8 > file_size:
            break
        cmd, cmdsize = struct.unpack_from("<II", data, offset)
        if cmdsize < 8 or offset + cmdsize > file_size:
            break
        if cmd == 0x19 and cmdsize >= 72:  # LC_SEGMENT_64
            segname = bytes(data[offset + 8 : offset + 24]).split(b"\x00", 1)[0]
            if segname == b"__LINKEDIT":
                fileoff, filesize = struct.unpack_from("<QQ", data, offset + 40)
                if fileoff > file_size:
                    break
                actual = file_size - fileoff
                if filesize != actual:
                    struct.pack_into("<Q", data, offset + 48, actual)
                    changed = True
                break
        offset += cmdsize
    if changed:
        with open(path, "wb") as fh:
            fh.write(data)
        print(f"adjusted __LINKEDIT filesize in {path}", flush=True)
    return changed


def is_system(dep):
    return dep.startswith((
        "/usr/lib/",
        "/System/",
        "/Library/Apple/",
    ))


def otool_deps(path):
    """Return dependent install names, excluding the file's own header line."""
    out = capture(["otool", "-L", path])
    deps = []
    for line in out.splitlines()[1:]:
        line = line.strip()
        if not line:
            continue
        # "path (compatibility version N, current version M[, weak])"
        dep = line.split(" (compatibility version", 1)[0].strip()
        if dep:
            deps.append(dep)
    return deps


def dylib_id(path):
    out = capture(["otool", "-D", path])
    lines = [ln.strip() for ln in out.splitlines() if ln.strip()]
    # Executables print only their path. Dylibs print the id on the next line.
    if len(lines) >= 2:
        return lines[1]
    return None


def rpaths(path):
    out = capture(["otool", "-l", path])
    found = []
    pending = False
    for line in out.splitlines():
        if "cmd LC_RPATH" in line:
            pending = True
            continue
        if pending and "path " in line:
            # "path /opt/homebrew/lib (offset 12)"
            part = line.strip().split("path ", 1)[1]
            found.append(part.split(" (offset", 1)[0].strip())
            pending = False
    return found


def framework_root(path):
    parts = path.split(os.sep)
    for i, part in enumerate(parts):
        if part.endswith(".framework"):
            return os.sep.join(parts[: i + 1])
    return None


def ensure_arm64(path):
    """Keep a single thin arm64 Mach-O.

    `lipo -archs` prints only "arm64" for both a thin file and a one-slice fat
    file. `lipo -thin` rejects an already-thin file, so only extract a slice
    when lipo reports a fat file.
    """
    archs = capture(["lipo", "-archs", path]).strip().split()
    if "arm64" not in archs:
        raise SystemExit(f"{path} is not arm64 (lipo -archs: {' '.join(archs)})")
    info = capture(["lipo", "-info", path])
    if "Non-fat" in info:
        return
    tmp = path + ".arm64"
    run(["lipo", path, "-thin", "arm64", "-output", tmp])
    os.replace(tmp, path)
    os.chmod(path, 0o755)


class MachOEditor:
    """Rewrite install names inside a thin little-endian Mach-O.

    Load-command strings are overwritten in place when the new path fits in
    the existing command. That avoids install_name_tool, which rejects some
    Homebrew binaries whose __LINKEDIT no longer matches the file size.
    """

    def __init__(self, path):
        self.path = path
        with open(path, "rb") as fh:
            self.data = bytearray(fh.read())
        magic = struct.unpack_from("<I", self.data, 0)[0]
        if magic != 0xFEEDFACF:
            raise SystemExit(f"{path} is not a thin little-endian Mach-O (magic {magic:#x})")
        self.ncmds = struct.unpack_from("<I", self.data, 16)[0]

    def commands(self):
        offset = 32
        for _ in range(self.ncmds):
            cmd, cmdsize = struct.unpack_from("<II", self.data, offset)
            if cmdsize < 8 or offset + cmdsize > len(self.data):
                raise SystemExit(f"bad load command in {self.path}")
            yield offset, cmd, cmdsize
            offset += cmdsize

    def _read_string(self, offset, cmdsize):
        name_off = struct.unpack_from("<I", self.data, offset + 8)[0]
        if name_off < 8 or name_off >= cmdsize:
            raise SystemExit(f"bad string offset in {self.path}")
        start = offset + name_off
        end = offset + cmdsize
        raw = bytes(self.data[start:end])
        nul = raw.find(b"\x00")
        if nul < 0:
            raise SystemExit(f"unterminated load-command string in {self.path}")
        return raw[:nul].decode(), start, end

    def _write_string(self, start, end, new):
        encoded = new.encode() + b"\x00"
        if len(encoded) > end - start:
            return False
        self.data[start : start + len(encoded)] = encoded
        for index in range(start + len(encoded), end):
            self.data[index] = 0
        return True

    def set_id(self, new):
        for offset, cmd, cmdsize in self.commands():
            if (cmd & ~0x80000000) != 0xD:  # LC_ID_DYLIB
                continue
            _old, start, end = self._read_string(offset, cmdsize)
            return self._write_string(start, end, new)
        return True

    def change(self, old, new):
        found = False
        for offset, cmd, cmdsize in self.commands():
            if (cmd & ~0x80000000) not in (0xC, 0xD, 0x18, 0x1F, 0x23):
                continue
            name, start, end = self._read_string(offset, cmdsize)
            if name != old:
                continue
            found = True
            if name != new and not self._write_string(start, end, new):
                return False
        return found

    def neutralize_rpaths(self):
        for offset, cmd, cmdsize in self.commands():
            if (cmd & ~0x80000000) != 0x1C:  # LC_RPATH
                continue
            name, start, end = self._read_string(offset, cmdsize)
            if not (name.startswith(FORBIDDEN_PREFIXES) or "/opt/homebrew" in name or "/usr/local" in name):
                continue
            if not self._write_string(start, end, "@loader_path"):
                return False
        return True

    def save(self):
        with open(self.path, "wb") as fh:
            fh.write(self.data)


def resolve_dep(dep, loader, exe_dir):
    if dep.startswith("/"):
        if os.path.exists(dep):
            return dep
        raise SystemExit(f"missing absolute dependency {dep} (from {loader})")

    rel = None
    base = None
    if dep.startswith("@loader_path/"):
        rel = dep[len("@loader_path/") :]
        base = os.path.dirname(loader)
    elif dep.startswith("@executable_path/"):
        rel = dep[len("@executable_path/") :]
        base = exe_dir
    elif dep.startswith("@rpath/"):
        rel = dep[len("@rpath/") :]
        search = []
        for rp in rpaths(loader):
            rp = rp.replace("@loader_path", os.path.dirname(loader))
            rp = rp.replace("@executable_path", exe_dir)
            search.append(os.path.normpath(os.path.join(rp, rel)))
        name = os.path.basename(rel)
        search.append(f"/opt/homebrew/lib/{name}")
        search.append(f"/usr/local/lib/{name}")
        search.extend(sorted(glob.glob(f"/opt/homebrew/opt/*/lib/{name}")))
        search.extend(sorted(glob.glob(f"/opt/homebrew/Cellar/*/*/lib/{name}")))
        # Framework-style @rpath/Foo.framework/...
        search.extend(sorted(glob.glob(f"/opt/homebrew/opt/*/{rel}")))
        search.extend(sorted(glob.glob(f"/opt/homebrew/lib/{rel}")))
        for cand in search:
            if os.path.exists(cand):
                return cand
        raise SystemExit(f"cannot resolve {dep} loaded by {loader}")
    else:
        raise SystemExit(f"unrecognized dependency {dep} loaded by {loader}")

    cand = os.path.normpath(os.path.join(base, rel))
    if os.path.exists(cand):
        return cand
    raise SystemExit(f"cannot resolve {dep} -> {cand} loaded by {loader}")


def fix_framework_layout(fw):
    """Keep Versions/Current and the top-level binary as relative symlinks."""
    versions = os.path.join(fw, "Versions")
    if not os.path.isdir(versions):
        return
    current = os.path.join(versions, "Current")
    version_dirs = []
    for entry in os.listdir(versions):
        if entry == "Current":
            continue
        path = os.path.join(versions, entry)
        if os.path.isdir(path) and not os.path.islink(path):
            version_dirs.append(entry)
    if os.path.lexists(current):
        if os.path.islink(current):
            target = os.readlink(current)
            target_ok = (not os.path.isabs(target)) and os.path.isdir(os.path.join(versions, target))
            if not target_ok:
                os.remove(current)
        else:
            return
    if not os.path.lexists(current):
        if len(version_dirs) != 1:
            raise SystemExit(f"cannot choose Versions/Current in {fw}: {version_dirs}")
        os.symlink(version_dirs[0], current)
    binary = os.path.splitext(os.path.basename(fw))[0]
    top = os.path.join(fw, binary)
    if not os.path.lexists(top) and os.path.exists(os.path.join(versions, "Current", binary)):
        os.symlink(os.path.join("Versions", "Current", binary), top)
    resources = os.path.join(fw, "Resources")
    cur_resources = os.path.join(versions, "Current", "Resources")
    if os.path.isdir(cur_resources) and not os.path.lexists(resources):
        os.symlink(os.path.join("Versions", "Current", "Resources"), resources)


def rewrite_external_symlinks(root):
    """Replace absolute Homebrew file symlinks inside a copied framework."""
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        for name in list(dirnames) + list(filenames):
            path = os.path.join(dirpath, name)
            if not os.path.islink(path):
                continue
            target = os.readlink(path)
            if not os.path.isabs(target) or not target.startswith(FORBIDDEN_PREFIXES):
                continue
            if not os.path.isfile(target):
                continue
            os.remove(path)
            shutil.copyfile(target, path)
            os.chmod(path, 0o755)


class Bundler:
    def __init__(self, app):
        self.app = app
        self.frameworks = os.path.join(app, "Contents", "Frameworks")
        self.exe = os.path.join(app, "Contents", "MacOS", "vkquake")
        self.exe_dir = os.path.dirname(self.exe)
        self.dep_to_rel = {}
        self.scanned = set()
        self.copied_frameworks = set()
        self.origin_of = {}

    def bundle(self):
        self._scan(self.exe)

    def _scan(self, binary):
        key = os.path.realpath(binary)
        if key in self.scanned:
            return
        self.scanned.add(key)
        ident = dylib_id(binary)
        for dep in otool_deps(binary):
            if ident and dep == ident:
                continue
            if is_system(dep):
                continue
            rel = self._ensure(dep, binary)
            prev = self.dep_to_rel.get(dep)
            if prev is not None and prev != rel:
                raise SystemExit(f"{dep} mapped to both {prev} and {rel}")
            self.dep_to_rel[dep] = rel

    def _ensure(self, dep, loader):
        resolved = resolve_dep(dep, loader, self.exe_dir)
        fw = framework_root(resolved)
        if fw:
            name = os.path.basename(fw)
            dest_fw = os.path.join(self.frameworks, name)
            if name not in self.copied_frameworks:
                if os.path.isdir(dest_fw):
                    shutil.rmtree(dest_fw)
                shutil.copytree(fw, dest_fw, symlinks=True)
                rewrite_external_symlinks(dest_fw)
                fix_framework_layout(dest_fw)
                self.copied_frameworks.add(name)
                for dirpath, dirnames, filenames in os.walk(dest_fw, followlinks=False):
                    for filename in filenames:
                        path = os.path.join(dirpath, filename)
                        if os.path.islink(path) or not is_macho(path):
                            continue
                        ensure_arm64(path)
                        self._scan(path)
            rel_inside = os.path.relpath(resolved, fw)
            return os.path.join(name, rel_inside)

        rel = os.path.basename(dep)
        dest = os.path.join(self.frameworks, rel)
        origin = os.path.realpath(resolved)
        if os.path.lexists(dest):
            if os.path.islink(dest) or not os.path.isfile(dest):
                raise SystemExit(f"refusing to overwrite non-file {dest}")
            prev = self.origin_of.get(rel)
            if prev != origin:
                raise SystemExit(f"basename collision for {rel}: {dep} ({origin}) != {prev}")
        else:
            os.makedirs(self.frameworks, exist_ok=True)
            shutil.copyfile(resolved, dest)
            os.chmod(dest, 0o755)
            self.origin_of[rel] = origin
            ensure_arm64(dest)
            print(f"bundled {dep} -> Contents/Frameworks/{rel}", flush=True)
            self._scan(dest)
        return rel

    def rewrite(self):
        machos = self.machos()
        for path in machos:
            self._rewrite_one(path)

    def machos(self):
        found = []
        for dirpath, dirnames, filenames in os.walk(self.app):
            for filename in filenames:
                path = os.path.join(dirpath, filename)
                if not os.path.islink(path) and is_macho(path):
                    found.append(path)
        return found

    def _new_ref(self, loader, rel):
        target = os.path.realpath(os.path.join(self.frameworks, rel))
        if os.path.samefile(loader, self.exe):
            return "@executable_path/../Frameworks/" + rel.replace(os.sep, "/")
        rel_from_loader = os.path.relpath(target, os.path.realpath(os.path.dirname(loader)))
        return "@loader_path/" + rel_from_loader.replace(os.sep, "/")

    def _install_name(self, cmd):
        try:
            run(cmd)
        except subprocess.CalledProcessError:
            raise SystemExit(
                f"install_name_tool failed: {' '.join(cmd)}. "
                "The binary may need -Wl,-headerpad_max_install_names."
            )

    def _rewrite_one(self, path):
        if os.path.samefile(path, self.exe):
            # The executable's new paths are longer than the Homebrew ids, so
            # they need the header pad added at link time.
            self._rewrite_with_install_name_tool(path)
        else:
            self._rewrite_inplace(path)

    def _rewrite_inplace(self, path):
        ident = dylib_id(path)
        editor = MachOEditor(path)
        if ident and self._forbidden_path(ident):
            base = os.path.basename(path)
            if not any(editor.set_id(cand) for cand in ("@loader_path/" + base, "@rpath/" + base)):
                raise SystemExit(f"no room to set id of {path} away from {ident}")
        seen = set()
        for dep in otool_deps(path):
            if ident and dep == ident:
                continue
            bundled = self.dep_to_rel.get(dep)
            if bundled is None or dep in seen:
                continue
            seen.add(dep)
            new = self._new_ref(path, bundled)
            alt = "@rpath/" + os.path.basename(bundled)
            if dep != new and not editor.change(dep, new) and not editor.change(dep, alt):
                raise SystemExit(f"no room to retarget {dep} -> {new} in {path}")
        if not editor.neutralize_rpaths():
            raise SystemExit(f"no room to rewrite rpaths in {path}")
        editor.save()
        print(f"rewrote install names in {path}", flush=True)

    @staticmethod
    def _forbidden_path(name):
        return name.startswith(FORBIDDEN_PREFIXES) or "/opt/homebrew" in name or "/usr/local" in name

    def _rewrite_with_install_name_tool(self, path):
        # Ad-hoc linker signatures block install_name_tool on modern macOS.
        # Removing one can leave __LINKEDIT.filesize past EOF; repair that
        # before rewriting install names.
        subprocess.call(["codesign", "--remove-signature", path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        fix_linkedit_filesize(path)
        ident = dylib_id(path)
        seen_changes = set()
        for dep in otool_deps(path):
            if ident and dep == ident:
                continue
            bundled = self.dep_to_rel.get(dep)
            if bundled is None or dep in seen_changes:
                continue
            new = self._new_ref(path, bundled)
            seen_changes.add(dep)
            if dep != new:
                self._install_name(["install_name_tool", "-change", dep, new, path])
        removed = set()
        for rp in rpaths(path):
            if rp in removed:
                continue
            if rp.startswith(FORBIDDEN_PREFIXES) or "/opt/homebrew" in rp or "/usr/local" in rp:
                removed.add(rp)
                self._install_name(["install_name_tool", "-delete_rpath", rp, path])


def make_icns(png_path, icns_path):
    iconset = tempfile.mkdtemp(suffix=".iconset")
    try:
        for size in (16, 32, 128, 256, 512):
            run(["sips", "-z", str(size), str(size), png_path, "--out", os.path.join(iconset, f"icon_{size}x{size}.png")])
            run([
                "sips", "-z", str(size * 2), str(size * 2), png_path,
                "--out", os.path.join(iconset, f"icon_{size}x{size}@2x.png"),
            ])
        run(["iconutil", "-c", "icns", iconset, "-o", icns_path])
    finally:
        shutil.rmtree(iconset, ignore_errors=True)


def parse_version_tuple(text):
    return tuple(int(part) for part in text.split("."))


def format_minos(version):
    if len(version) == 1:
        return f"{version[0]}.0"
    return ".".join(str(part) for part in version[:3])


def detect_minos(machos):
    floor = (13, 0)
    highest = floor
    for path in machos:
        try:
            out = capture(["vtool", "-arch", "arm64", "-show-build", path])
        except subprocess.CalledProcessError:
            out = capture(["vtool", "-show-build", path])
        for line in out.splitlines():
            line = line.strip()
            if not line.startswith("minos "):
                continue
            ver = parse_version_tuple(line.split()[1])
            if ver > highest:
                highest = ver
    return format_minos(highest)


def write_plist(path, version, minos, has_icon):
    plist = {
        "CFBundleName": "vkQuake",
        "CFBundleDisplayName": "vkQuake",
        "CFBundleIdentifier": "io.github.novum.vkquake",
        "CFBundleVersion": version,
        "CFBundleShortVersionString": version,
        "CFBundlePackageType": "APPL",
        "CFBundleSignature": "????",
        "CFBundleExecutable": "vkquake",
        "CFBundleInfoDictionaryVersion": "6.0",
        "CFBundleDevelopmentRegion": "en",
        "CFBundleSupportedPlatforms": ["MacOSX"],
        "LSMinimumSystemVersion": minos,
        "LSApplicationCategoryType": "public.app-category.games",
        "NSHighResolutionCapable": True,
        "NSRequiresAquaSystemAppearance": False,
    }
    if has_icon:
        plist["CFBundleIconFile"] = "vkQuake"
    with open(path, "wb") as fh:
        plistlib.dump(plist, fh, fmt=plistlib.FMT_XML)


def write_molten_icd(resources, frameworks):
    molten = None
    for dirpath, dirnames, filenames in os.walk(frameworks):
        for filename in filenames:
            if filename == "libMoltenVK.dylib" or filename.startswith("libMoltenVK"):
                molten = os.path.join(dirpath, filename)
                break
    if molten is None:
        raise SystemExit("MoltenVK was not bundled into Contents/Frameworks")
    icd_dir = os.path.join(resources, "vulkan", "icd.d")
    os.makedirs(icd_dir, exist_ok=True)
    rel = os.path.relpath(molten, icd_dir).replace(os.sep, "/")
    icd = {
        "file_format_version": "1.0.0",
        "ICD": {
            "library_path": rel,
            "api_version": "1.4.341",
        },
    }
    with open(os.path.join(icd_dir, "MoltenVK_icd.json"), "w", encoding="utf-8") as fh:
        json.dump(icd, fh, indent=2)
        fh.write("\n")


def sign_inside_out(app):
    subprocess.call(["xattr", "-cr", app])
    machos = []
    frameworks = []
    for dirpath, dirnames, filenames in os.walk(app):
        for dirname in dirnames:
            if dirname.endswith(".framework"):
                frameworks.append(os.path.join(dirpath, dirname))
        for filename in filenames:
            path = os.path.join(dirpath, filename)
            if not os.path.islink(path) and is_macho(path):
                machos.append(path)
    machos.sort(key=lambda path: path.count(os.sep), reverse=True)
    for path in machos:
        run(["codesign", "--force", "--sign", "-", "--timestamp=none", path])
    frameworks.sort(key=lambda path: path.count(os.sep), reverse=True)
    for path in frameworks:
        run(["codesign", "--force", "--sign", "-", "--timestamp=none", path])
    run(["codesign", "--force", "--sign", "-", "--timestamp=none", app])


def verify_codesign(app):
    run(["codesign", "--verify", "--deep", "--strict", "--verbose=2", app])


def verify_layout(app):
    for dirpath, dirnames, filenames in os.walk(app, followlinks=False):
        for name in list(dirnames) + list(filenames):
            path = os.path.join(dirpath, name)
            if os.path.islink(path) and not os.path.exists(path):
                raise SystemExit(f"dangling symlink: {path} -> {os.readlink(path)}")
        for dirname in dirnames:
            if not dirname.endswith(".framework"):
                continue
            fw = os.path.join(dirpath, dirname)
            versions = os.path.join(fw, "Versions")
            if not os.path.isdir(versions):
                continue
            current = os.path.join(versions, "Current")
            if not os.path.islink(current):
                raise SystemExit(f"{current} must be a relative Versions/Current symlink")
            target = os.readlink(current)
            if os.path.isabs(target) or not os.path.isdir(os.path.join(versions, target)):
                raise SystemExit(f"Versions/Current in {fw} is not a relative link to a version directory ({target})")


def verify_machos(app):
    report = []
    for dirpath, dirnames, filenames in os.walk(app):
        for filename in filenames:
            path = os.path.join(dirpath, filename)
            if os.path.islink(path) or not is_macho(path):
                continue
            archs = capture(["lipo", "-archs", path]).strip()
            if archs != "arm64":
                raise SystemExit(f"lipo -archs {path}: {archs!r} (expected arm64)")
            libs = capture(["otool", "-L", path])
            load = capture(["otool", "-l", path])
            for label, text in (("otool -L", libs), ("otool -l", load)):
                for prefix in ("/opt/homebrew", "/usr/local"):
                    if prefix in text:
                        raise SystemExit(f"{label} of {path} still references {prefix}:\n{text}")
            report.append(f"## {path}\n# lipo -archs: {archs}\n{libs}")
    return "\n".join(report)


def smoke(binary):
    binary = os.path.abspath(binary)
    basedir = tempfile.mkdtemp(prefix="vkquake-nodata-")
    print(f"smoke: {binary}", flush=True)
    try:
        proc = subprocess.run(
            [binary, "-dedicated", "-basedir", basedir, "-nosteam", "-nogog", "-noegs", "-noepic"],
            cwd="/tmp",
            capture_output=True,
            text=True,
            timeout=45,
        )
    except subprocess.TimeoutExpired as exc:
        sys.stdout.write(exc.stdout or "")
        sys.stderr.write(exc.stderr or "")
        raise SystemExit("smoke test timed out (binary did not exit without game data)")
    sys.stdout.write(proc.stdout or "")
    sys.stderr.write(proc.stderr or "")
    text = (proc.stdout or "") + (proc.stderr or "")
    if proc.returncode == 0:
        raise SystemExit("smoke test expected a non-zero exit without game data")
    if "pak0.pak" not in text:
        raise SystemExit("smoke test output did not mention pak0.pak")
    print(f"smoke ok (exit {proc.returncode})", flush=True)


def make_dmg(app, dmg_path, volume):
    stage = tempfile.mkdtemp(prefix="vkquake-dmg-")
    try:
        dest = os.path.join(stage, "vkQuake.app")
        run(["ditto", app, dest])
        os.symlink("/Applications", os.path.join(stage, "Applications"))
        if os.path.exists(dmg_path):
            os.remove(dmg_path)
        run([
            "hdiutil", "create",
            "-volname", volume,
            "-srcfolder", stage,
            "-ov",
            "-format", "UDZO",
            dmg_path,
        ])
    finally:
        shutil.rmtree(stage, ignore_errors=True)


def verify_dmg(dmg_path):
    mount = tempfile.mkdtemp(prefix="vkquake-mnt-")
    attached = False
    try:
        run(["hdiutil", "attach", "-nobrowse", "-readonly", "-mountpoint", mount, dmg_path])
        attached = True
        mounted = os.path.join(mount, "vkQuake.app")
        if not os.path.isdir(mounted):
            raise SystemExit(f"DMG does not contain vkQuake.app (contents: {os.listdir(mount)})")
        apps = os.path.join(mount, "Applications")
        if not os.path.islink(apps) or os.readlink(apps) != "/Applications":
            raise SystemExit("DMG is missing the /Applications symlink")
        verify_codesign(mounted)
        verify_layout(mounted)
        verify_machos(mounted)
        # The disk image is read-only. Run a copy of the mounted app so the
        # smoke test exercises the bytes that were actually archived.
        extracted = tempfile.mkdtemp(prefix="vkquake-from-dmg-")
        try:
            run(["ditto", mounted, os.path.join(extracted, "vkQuake.app")])
            smoke(os.path.join(extracted, "vkQuake.app", "Contents", "MacOS", "vkquake"))
        finally:
            shutil.rmtree(extracted, ignore_errors=True)
    finally:
        if attached:
            subprocess.call(["hdiutil", "detach", mount])
        shutil.rmtree(mount, ignore_errors=True)


def parse_source_version(source):
    header = os.path.join(source, "Quake", "quakever.h")
    major = minor = patch = None
    with open(header, encoding="utf-8") as fh:
        for line in fh:
            if line.startswith("#define VKQUAKE_VERSION_MAJOR"):
                major = int(line.split()[-1])
            elif line.startswith("#define VKQUAKE_VERSION_MINOR"):
                minor = int(line.split()[-1])
            elif line.startswith("#define VKQUAKE_VER_PATCH"):
                patch = int(line.split()[-1])
    if None in (major, minor, patch):
        raise SystemExit(f"could not parse version from {header}")
    return f"{major}.{minor}.{patch}"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--version", required=True)
    args = parser.parse_args()

    source_version = parse_source_version(args.source)
    if source_version != args.version:
        raise SystemExit(f"source version {source_version} does not match --version {args.version}")

    binary = os.path.abspath(args.binary)
    if not is_macho(binary):
        raise SystemExit(f"not a Mach-O binary: {binary}")

    out = os.path.abspath(args.output)
    os.makedirs(out, exist_ok=True)
    app = os.path.join(out, "vkQuake.app")
    if os.path.exists(app):
        shutil.rmtree(app)
    macos = os.path.join(app, "Contents", "MacOS")
    resources = os.path.join(app, "Contents", "Resources")
    os.makedirs(macos)
    os.makedirs(resources)
    exe = os.path.join(macos, "vkquake")
    shutil.copyfile(binary, exe)
    os.chmod(exe, 0o755)
    ensure_arm64(exe)

    bundler = Bundler(app)
    bundler.bundle()
    if not bundler.dep_to_rel:
        raise SystemExit("no non-system libraries were bundled; MoltenVK should have been copied")
    bundler.rewrite()

    png = os.path.join(args.source, "Misc", "vkQuake_512.png")
    has_icon = os.path.isfile(png)
    if has_icon:
        make_icns(png, os.path.join(resources, "vkQuake.icns"))
    else:
        print(f"no icon at {png}; Info.plist will omit CFBundleIconFile", flush=True)

    write_molten_icd(resources, bundler.frameworks)
    minos = detect_minos(bundler.machos())
    write_plist(os.path.join(app, "Contents", "Info.plist"), args.version, minos, has_icon)
    with open(os.path.join(out, "minos.txt"), "w", encoding="utf-8") as fh:
        fh.write(minos + "\n")

    verify_layout(app)
    sign_inside_out(app)
    verify_codesign(app)
    verify_layout(app)
    report = verify_machos(app)
    with open(os.path.join(out, "bundle-report.txt"), "w", encoding="utf-8") as fh:
        fh.write(report)
    print(report)
    smoke(exe)

    dmg = os.path.join(out, f"vkQuake-{args.version}-macos-arm64.dmg")
    zip_path = os.path.join(out, f"vkQuake-{args.version}-macos-arm64.zip")
    make_dmg(app, dmg, f"vkQuake {args.version}")
    if os.path.exists(zip_path):
        os.remove(zip_path)
    run(["ditto", "-c", "-k", "--keepParent", app, zip_path])
    verify_dmg(dmg)
    print(f"minos {minos}", flush=True)
    print(f"wrote {dmg}", flush=True)
    print(f"wrote {zip_path}", flush=True)


if __name__ == "__main__":
    main()
