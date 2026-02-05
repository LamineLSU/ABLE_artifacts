rule Bypass_Evasion
{
    meta:
        description = "Evasion bypass detection rules targeting specific security points"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 FF C3 E8 CE E8 74 FA FF FF E8 B5 FC FF FF 53 FF CE EC 0D FF 15 2C A1 0C 00 }
        $pattern1 = { 6A 5B 5A 8B E8 25 05 00 00 F8 43 3F DF FF 8B 4D FC E8 4B 17 00 00 A1 88 85 15 00 FF 15 88 A0 15 00 }
        $pattern2 = { 6A 40 53 E8 FF D4 01 00 00 0F 8B E5 E8 0D 0C 00 C3 FF 15 2C A1 15 00 FF 15 88 A0 11 50 }
    
    condition:
        any of them
}