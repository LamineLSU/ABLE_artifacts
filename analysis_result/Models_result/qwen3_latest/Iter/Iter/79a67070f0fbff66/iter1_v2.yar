rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 83 3D ?? ?? ?? ?? ?? 74 ?? }  // CMP + JE conditional check
        $pattern1 = { FF 15 18 50 61 00 }             // Call to CryptReleaseContext
        $pattern2 = { FF 15 A4 50 61 00 }             // Call to ExitProcess

    condition:
        any of them
}