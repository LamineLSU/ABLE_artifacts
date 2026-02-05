rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule - Bypass conditional jump"
        cape_options = "bp0=$pattern0+0,action0=skip,count=0"

    strings:
        $pattern0 = { 0F 84 ?? ?? ?? ?? 8B 45 }

    condition:
        any of them
}