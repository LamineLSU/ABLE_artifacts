rule Bypass_Sample_1
{
    meta:
        description = "Bypass initial CALL"
        cape_options = "bp0=$pattern0+0,action0=skip"

    strings:
        $pattern0 = { FF 15 2C A1 ?? ?? ?? ?? 33 FF }

    condition:
        any of them
}