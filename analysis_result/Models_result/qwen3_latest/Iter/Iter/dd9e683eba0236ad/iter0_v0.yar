rule ExitProcess_Call
{
    meta:
        description = "Detects call to ExitProcess (Kernel32.dll)"
        cape_options = "bp0=$a+0,action0=skip,count=0"
    strings:
        $a = { 52 83 C4 ?? 52 FF D0 }
    condition:
        $a
}