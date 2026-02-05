rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - targeting exit decisions and specific conditions"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 8B CE 85 C0 0F 84 33 FD FF FF 8B CE 74 12 8B CE }
        $pattern1 = { E8 E3 FA FF FF 6A 40 00 01 51 D6 00 00 00 00 00 }
        $pattern2 = { 8B C7 EB 03 C3 49 A1 2C }
}

condition:
    (any of the patterns match at any location)