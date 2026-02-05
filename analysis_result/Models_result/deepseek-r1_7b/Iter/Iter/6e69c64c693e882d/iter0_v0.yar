rule Bypass_Evasion
{
    meta:
        description = "Evasion bypass detection"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,count=0"

    strings:
        $pattern0 = { 8B EC F3 FF7508 E8C8FFFFF FF15ACB04100 } (This pattern captures the first bypass attempt with an extra push instruction.)
        $pattern1 = { 59 5A F3 FF7508 FF15ACB04100 } (This pattern targets another bypass path without the initial push, focusing on the post-call steps.)
        $pattern2 = { 6A ?? 5A F3 FF7508 FF15ACB04100 } (This pattern captures a different instruction sequence used for bypassing.)
}

 cape: {
     "default": "unknown"
 }