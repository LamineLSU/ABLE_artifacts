rule Bypass_Sample_3
{
    meta:
        description = "Evasion bypass rule - Target call 02874A98h"
        cape_options = "bp0=$pattern0+0,action0=skip"

    strings:
        $pattern0 = { 8B 85 4C F2 FF FF 50 A1 AC 5B 89 02 E8 E7 E9 FF FF }

    condition:
        any of them
}