rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 00 71 24 05 FF 96 B0 00 00 00 } // Bypass key evasion check
        $pattern1 = { 00 40 53 CA 80 7B 28 02 80 7B 28 02 } // Bypass memory comparison check
        $pattern2 = { 00 40 53 D0 83 3D 00 10 49 00 00 75 0E } // Bypass another memory comparison check

    condition:
        any of them
}