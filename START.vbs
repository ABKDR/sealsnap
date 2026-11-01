Option Explicit
Dim shell, fs, root, python
Set shell = CreateObject("WScript.Shell")
Set fs = CreateObject("Scripting.FileSystemObject")
root = fs.GetParentFolderName(WScript.ScriptFullName)
python = root & "\.venv\Scripts\pythonw.exe"
If Not fs.FileExists(python) Then
  MsgBox "Python environment missing. See README.md.", 16, "SealSnap"
  WScript.Quit 1
End If
shell.CurrentDirectory = root
shell.Run """" & python & """ -B -m sealsnap gui", 0, False
