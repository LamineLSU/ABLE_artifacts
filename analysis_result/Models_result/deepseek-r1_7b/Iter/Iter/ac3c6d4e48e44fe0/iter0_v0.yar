rule Bypass_Sample
{
    meta:
        description = "Evasion bypass patterns targeting memory and stack manipulation"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B FF 55 8B EC FF 75 08 E8 C8 FF FF FF 33 FF 8B 45 0F 84 ?? ?? ?? ?? ?? }
        $pattern1 = { 6A 5A 53 FF 75 08 FF E5 8B EC 4B 85 C0 33 DB BA 21 05 ?? ?? ?? ?? E8 0D 0C 00 ?? ?? }
        $pattern2 = { 6A 5A 53 FF 75 08 FF 75 08 FF E5 8B EC 4B 85 C0 33 DB BA 21 05 ?? ?? ?? E8 0D 0C 00 ?? ?? }

    condition:
        (any_of($pattern0, $pattern1, $pattern2))
}