rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule targeting function calls"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? E8 ?? ?? ?? ?? }
        $pattern1 = { DD C6 F9 3E 8D 7B FF EC 0C 8D 7B FE 00 FF 55 5A FA 52 00 5A 7E 00 5A FF 4F 56 CC D1 8B DF 95 E5 DD 53 48 F5 5C CA EC C3 ED 5D 6A 35 ??
                     6A 00 51 5E 52 FC DC 7D 5D 6A 00 51 5E 52 FC DC 7D CC FF 5C 9F 48 F5 5C CA EC C3 ED 5D 6A 35 ??
                     DD 35 ?? ?? ?? ?? 8B DF 95 E5 DD 53 48 F5 5C CA EC C3 ED 5D 6A 00 51 5E 52 FC DC 7D 5D 6A 00 51 5E }
        $pattern2 = { D9 CC ?? ?? ?? ?? ??
                     ?? ?? ?? ?? F8 BC ??
                     5B BB EC CB ED 4C 4F 03 CA FF ?? ?? ?? ?? 7D 5E 6A 35 ??
                     8B DF 95 E5 DD 53 48 F5 5C CA EC C3 ED 5D 6A 00 51 5E 52 FC DC 7D 5D 6A 00 51 5E }

    condition:
        any of them
}