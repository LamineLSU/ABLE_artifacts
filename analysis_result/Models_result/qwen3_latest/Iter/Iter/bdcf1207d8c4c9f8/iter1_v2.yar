rule CustomRule
{
    meta:
        description = "Detects specific push and call sequences in the given binary"
        cape_options = "bp0=$push_call_1+0,action0=skip,bp1=$call_exitprocess+0,action1=skip,bp2=$push_call_2+0,action2=skip,count=0"
        author = "Your Name"
        date = "2023-10-10"

    strings:
        $push_call_1 = { FF 75 08 E8 ?? ?? ?? ?? }
        $call_exitprocess = { FF 15 AC B0 41 00 }
        $push_call_2 = { FF 75 08 FF 15 AC B0 41 00 }

    condition:
        all of (
            $push_call_1 or
            $call_exitprocess or
            $push_call_2
        )
}