rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B CE E8 74 FA FF FF 85 C0 0F 84 33 FD FF FF } //Trace 1: CALL instruction at 012F619E.  Includes the preceding test and conditional jump.
        $pattern1 = { E8 C8 FF FF FF 59 FF 75 08 } //Trace 2 & 3: CALL instruction at 0040E7F6. Includes surrounding push and pop.
        $pattern2 = { FF 15 AC B0 41 00 59 FF 75 08 } //Trace 2 & 3: CALL instruction at 0040E7FF. Includes surrounding push and pop.

    condition:
        any of them
}