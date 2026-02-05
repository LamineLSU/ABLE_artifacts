rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule - Call bypass"
        cape_options = "bp0=$pattern0+0,action0=skip,count=0"

    strings:
        $pattern0 = { 55 8B EC E8 C8 FF FF FF ?? }

    condition:
        any of them
}