rule Bypass_Sample_Call1
{
    meta:
        description = "Bypass CALL to 0040E7C3 (Anti-VM/Debug)"
        cape_options = "bp0=$pattern0+0,action0=skip"

    strings:
        $pattern0 = { 8B FF 55 E8 C8 FF FF FF }

    condition:
        any of them
}