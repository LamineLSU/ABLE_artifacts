rule ExitCheck
{
    meta:
        description = "Detects a sequence involving push and call to CRT exit function"
        cape_options = "bp0=$push_call+0,action0=skip,count=0"
    strings:
        $push_call = { 55 8B EC FF 75 08 E8 ?? ?? ?? ?? }
    condition:
        $push_call
}