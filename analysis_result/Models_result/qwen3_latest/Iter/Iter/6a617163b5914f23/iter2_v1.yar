rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF 15 ?? ?? ?? ?? }  // CALL to lstrcat/ShellExecuteEx
        $pattern1 = { C7 85 ?? ?? ?? ?? }  // MEMSET data initialization
        $pattern2 = { E8 ?? ?? ?? ?? }      // CALL to _memset (relative jump)

    condition:
        any of them
}