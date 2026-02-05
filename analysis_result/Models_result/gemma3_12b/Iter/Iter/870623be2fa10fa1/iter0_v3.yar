rule Bypass_Sample_3
{
    meta:
        description = "Bypass direct CALL"
        cape_options = "bp0=$pattern0+0,action0=skip"

    strings:
        $pattern0 = { 55 8B FF 55 8B EC E8 C8 FF FF FF }

    condition:
        any of them
}