rule Bypass_Sample_Call1
{
    meta:
        description = "Bypass CALL at 0040E7F6"
        cape_options = "bp0=$pattern0+0,action0=skip"

    strings:
        $pattern0 = { 8B FF 55 8B EC FF 75 08 E8 C8 FF FF FF }

    condition:
        all of them
}