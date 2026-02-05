rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? CC }  // ExitProcess call + int3
        $pattern1 = { 6A 00 E8 ?? ?? ?? ?? }  // push 0 + exit call
        $pattern2 = { E8 6E FF FF FF 6A 00 }  // Initial call + push 0

    condition:
        any of them
}