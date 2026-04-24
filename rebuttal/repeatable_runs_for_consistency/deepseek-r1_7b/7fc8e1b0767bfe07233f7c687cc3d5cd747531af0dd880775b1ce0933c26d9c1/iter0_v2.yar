rule Bypass_Sample
{
    meta:
        description = "Evasion bypass using known exit addresses"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B EC FF C8 5A 8B CE E8 ?? ?? ?? ?? 8B 45 }  // Surrounding context + exit call
        $pattern1 = { 8B F3 FF 75 08 FF C8 FF FF FF }                   // Exit call with minimal context
        $pattern2 = { 6A EC FF C8 FF F7 FF 9D 8C 8E FF F5 FF 4A }   // Another exit call variant

    condition:
        any of them
}