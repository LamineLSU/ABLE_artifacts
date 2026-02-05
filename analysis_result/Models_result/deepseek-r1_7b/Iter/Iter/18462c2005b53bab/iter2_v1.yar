rule Bypass_Evasion
{
    meta:
        description = "Detects various bypassed call instructions in x86"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 FF C8 FF FF ?? }  // Represents a long jump call with displacement
        $pattern1 = { 00 0F 15 AC B0 41 00 }  // Part of the second exit point
        $pattern2 = { FF 75 08 E8 C8 FF FF ?? }  // Another call instruction with displacement
    condition:
        any_of them
}