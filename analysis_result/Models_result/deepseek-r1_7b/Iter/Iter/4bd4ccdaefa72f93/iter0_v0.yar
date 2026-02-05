rule Bypass_Evasion
{
    meta:
        description = "Evasion bypass detection"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 48 8D 4C 24 60 EA CD 60 48 89 74 24 30 30 45 33 C9 9D 9D 89 74 24 28 DD 28 45 33 C0 8D 8D BA 00 00 00 C0 ED C0 00 00 00 C7 44 24 20 02 00 00 00 DD 20 00 00 00 02 FF 15 F1 0E 00 00 CA 00 00 7F F7 2B A5 20 08 48 8B F8 DA 48 83 F8 FF CA FF FF FF FF FF FF FF FF 74 4E 00 00 7F F7 2B A5 11 6E } 
        $pattern1 = { 48 8D 8D 90 01 00 00 EA 9D 00 00 01 90 48 89 9D 98 01 00 00 DB 00 00 01 98 44 8D 46 08 EA 8D DD 08 48 89 74 24 20 20 48 8D 95 98 01 00 00 EA DD 00 00 01 98 48 8B C8 CA FF 15 E9 0E 00 00 CA 00 00 7F F7 2B A5 20 30 4C 8D 8D 90 01 00 00 EA 9D 00 00 01 90 48 89 74 24 20 20 44 8D 46 14 EA 8D DD 14 48 8B CF CD 48 8D 54 24 40 EA DD 40 FF 15 CB 0E 00 00 CA 00 00 7F F7 2B A5 20 30 48 8B CF CD FF 15 AA 0E 00 00 CA 00 00 7F F7 2B A5 20 18 } 
        $pattern2 = { 6A ?? 5A 8B CE E8 6A ?? 5A 8B CB ?? 33 C9 EC EC FF 15 B2 0E 00 00 CA 00 00 7F F7 2B A5 20 28 } 

    condition:
        (any of them)
}