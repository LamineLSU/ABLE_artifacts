rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? E8 F7 25 00 00 00 FF 55 }
        $pattern1 = { 64 A1 30 00 00 00 00 00 00 8B CE E8 ?? ?? ?? ?? 53 }

    condition:
        any of them
}