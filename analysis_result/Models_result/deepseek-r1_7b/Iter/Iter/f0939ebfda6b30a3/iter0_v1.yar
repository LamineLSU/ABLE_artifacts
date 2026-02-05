rule Bypass_Sample
{
    meta:
        description = "Evasion bypass patterns"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 B2 FF FF C1 E8 A8 01 FF 75 C4 E9 FF }
        $pattern1 = { 89 45 C0 FF 75 C4 E8 B2 FF FF C1 E8 }
        $pattern2 = { 8B 5D FF 75 BC E8 B2 FF FF C1 E8 }

    condition:
        any of them
}