rule MaliciousCodePattern
{
    meta:
        description = "Detects suspicious code patterns based on known memory dump"
        cape_options = "bp0=$push_call1+0,action0=skip,bp1=$push_call2+0,action1=skip,bp2=$pop_push_call+0,action2=skip,count=0"
        author = "YourName"
        date = "2025-04-15"

    strings:
        $push_call1 = { FF 75 08 E8 ?? ?? ?? ?? }
        $push_call2 = { FF 75 08 FF 15 ?? ?? ?? ?? }
        $pop_push_call = { 59 FF 75 08 FF 15 ?? ?? ?? ?? }

    condition:
        any of them
}