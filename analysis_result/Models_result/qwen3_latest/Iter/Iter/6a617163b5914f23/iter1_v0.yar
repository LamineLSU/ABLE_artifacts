rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 83 C4 18 53 FF 15 ?? ?? ?? ?? }  // Add ESP, push EBX, CALL (ExitProcess)
        $pattern1 = { FF 15 20 75 45 00 }              // CALL to lstrcat@KERNEL32
        $pattern2 = { FF 15 84 75 45 00 }              // CALL to ShellExecuteEx@SHELL32

    condition:
        any of them
}