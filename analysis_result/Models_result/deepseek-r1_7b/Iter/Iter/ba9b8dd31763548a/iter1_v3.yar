rule Bypass_Sample
{
    meta:
        description = "Evasion bypass detection"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B CE E8 CE 25 05 00 ?? }
        $pattern1 = { FF 15 AC B0 41 00 5F 0F 84 8B CE ?? }
        $pattern2 = { E8 C8 FF FF FF 59 FF 15 08 C8 C5 ?? }

    condition:
        any of them
}