"""Instrument only the isolated diagnostic APK; never edit the shared module cache."""
import json, os, pathlib, shutil, subprocess
module = "github.com/sagernet/gvisor"
subprocess.run(["go", "mod", "download", module], check=True)
source = pathlib.Path(json.loads(subprocess.check_output(["go", "list", "-m", "-json", module]))["Dir"])
target = pathlib.Path(os.environ["RUNNER_TEMP"]) / "gvisor-reader-diagnostic"
shutil.copytree(source, target)
path = target / "pkg/tcpip/link/fdbased/endpoint.go"
content = path.read_text()
before = "\t\tif err != nil || !cont {"
assert content.count(before) == 1
content = content.replace(before, before + '\n\t\t\tfmt.Printf("LineVpnFdbased reader exit: err=%v continue=%v\\n", err, cont)')
path.chmod(0o600)
path.write_text(content)
subprocess.run(["go", "mod", "edit", "-replace=" + module + "=" + str(target)], check=True)
