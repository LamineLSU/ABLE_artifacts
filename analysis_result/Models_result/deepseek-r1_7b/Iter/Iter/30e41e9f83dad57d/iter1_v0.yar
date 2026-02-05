rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - conditional checks before exit decision"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 55 8B EC 51 53 56 57 BE 00 30 00 00 FF 15 BC 36 61 00 50 FF 15 58 37 61 00 F3 AA }
        $pattern1 = { 55 8B EC 83 E4 F8 83 EC 40 6A 40 33 C0 FF 75 FC 50 FF 15 3C 36 61 00 8A C9 }
        $pattern2 = { 55 8B EC 83 E4 F8 83 EC 40 6A 40 33 C0 FC FF 75 FC 50 FF 15 3C 36 61 00 FC }

    condition:
        any of them
}