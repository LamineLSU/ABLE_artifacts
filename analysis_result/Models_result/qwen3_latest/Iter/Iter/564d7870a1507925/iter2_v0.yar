rule ExitProcessCheck
{
    meta:
        description = "Detects potential evasion checks or direct calls to ExitProcess"
        cape_options = "bp0=$cmp+0,action0=skip,bp1=$jnc_call+0,action1=skip,bp2=$push_call+0,action2=skip,count=0"
        confidence = 70

    strings:
        $cmp = { 66 81 3C 24 E4 07 }
        $jnc_call = { 73 07 E8 ?? ?? ?? ?? }
        $push_call = { 6A 00 E8 ?? ?? ?? ?? }

    condition:
        all of them
}