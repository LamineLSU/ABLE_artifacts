rule Bypass_Sample
{
    meta:
        description = "Evasion bypass for exit process check"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 55 0C 5E ED EB 0C ?? ?? 8B 55 0C 5E ED EB 0C ?? ?? 8B 45 08 8B 45 08 EA EB 08 ?? ?? }
        $pattern1 = { E8 74 0A 00 00 E8 74 0A 00 00 CA 00 41 EB 47 ?? ?? 56 ?? 56 ?? 6A 36 00 00 00 36 ?? }
        $pattern2 = { FF D0 FF D0 CA EA ?? ?? 8B 55 0C EA ?? ?? 8B 06 EA ?? ?? AD 14 ?? ED ?? }
    condition:
        any of them
}