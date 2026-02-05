rule Bypass_Sample_3
{
    meta:
        description = "Bypass call 00DBE18Ch"
        cape_options = "bp0=$pattern0+0,action0=skip"

    strings:
        $pattern0 = { 8B FF 55 8B EC E8 0B 00 00 00 59 FF 75 08 FF 15 ?? ?? ?? ?? }

    condition:
        any of them
}