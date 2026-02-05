rule Bypass_Sample
{
    meta:
        description = "Evasion bypass by bypassing specific function calls identified through trace analysis."
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 59 C0 0F 84 ?? ?? ?? } // Bypass around the first function call in TRACE //1 and //2.
        $pattern1 = { E8 D1 FF FF FF ?? ?? } // Bypass around a common function call used across multiple traces.
        $pattern2 = { FF 75 08 04 00 ?? } // Bypass around a unique instruction in TRACE //3.

    condition:
        any of them
}