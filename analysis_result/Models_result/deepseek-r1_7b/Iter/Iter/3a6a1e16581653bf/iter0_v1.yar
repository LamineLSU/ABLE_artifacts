rule Bypass_Sample
{
    meta:
        description = "Evasion bypass patterns targeting function calls"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B CE 5A FF 75 08 E8 C8 FF FF FF }  // Targeting the function call in TRACE //3 and #4
        $pattern1 = { 6A 40 8B CE E8 25 05 00 00 }       // Bypassing the first function call in TRACE //1
        $pattern2 = { FF 75 08 E8 C8 FF FF FF E8 1F }      // Skipping a conditional jump before a function call

    condition:
        any of them
}