rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }
        $pattern1 = { E8 74 FA FF FF CA 01 35 5C 17 AD AC }
        $pattern2 = { 8D 95 F0 FE FF FF EA ED DD EB 00 00 01 10 CB ED DC }

    condition:
        any of them
}