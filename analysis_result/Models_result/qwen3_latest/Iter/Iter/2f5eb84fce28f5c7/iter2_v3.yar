rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 8D 95 ?? ?? ?? ?? }  // Early test+je + lea
        $pattern1 = { E8 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? }  // Call + test+je
        $pattern2 = { 74 07 FF 15 ?? ?? ?? ?? }  // je + API call (ExitProcess)

    condition:
        any of them
}