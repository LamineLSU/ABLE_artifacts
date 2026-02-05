rule Bypass_Sample_1
{
    meta:
        description = "Evasion bypass: Skip CALL 0040E7C3h"
        cape_options = "bp0=$pattern0+0,action0=skip,count=0"

    strings:
        $pattern0 = { E8 C8 FF FF FF ?? ?? ?? ?? }

    condition:
        any of them
}