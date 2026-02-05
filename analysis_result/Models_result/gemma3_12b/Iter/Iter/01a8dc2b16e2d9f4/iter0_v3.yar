rule Bypass_Sample_1
{
    meta:
        description = "Evasion bypass rule - Call instruction bypass"
        cape_options = "bp0=$pattern0+0,action0=skip"

    strings:
        $pattern0 = { 55 8B EC 8B FF 55 8B EC E8 C8 FF FF FF }

    condition:
        any of them
}