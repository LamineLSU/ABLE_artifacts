rule ExitProcessCodeFlow
{
    meta:
        description = "Detects code flow involving push, call to ExitProcess, and jump instructions."
        cape_options = "bp0=$push_call+0,action0=skip,bp1=$call_jump+0,action1=skip,bp2=$jump+0,action2=skip,count=0"

    strings:
        $push_call = { 6A 00 6A 00 E8 90 }
        $call_jump = { E8 90 00 00 00 FF 25 }
        $jump = { FF 25 EC 40 40 00 }

    condition:
        all of them
}