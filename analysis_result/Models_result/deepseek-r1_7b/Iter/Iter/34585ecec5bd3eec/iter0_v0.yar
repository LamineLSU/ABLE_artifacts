rule Bypass_Sample
{
    meta:
        description = "Evasion bypass patterns targeting specific instruction sequences"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 5A ?? FF 75 08 8B 45 E8 C8 FF FF }
        $pattern1 = { 6A ?? FF 75 08 8B EC E8 8D 03 FF }
        $pattern2 = { BA 04 53 FF 75 08 8B 99 E8 0D 04 FF }

    condition:
        any of them
}