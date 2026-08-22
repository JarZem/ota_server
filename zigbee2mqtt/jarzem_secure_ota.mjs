import {presets as e, access as ea} from 'zigbee-herdsman-converters/lib/exposes';
import * as m from 'zigbee-herdsman-converters/lib/modernExtend';
import {Zcl} from 'zigbee-herdsman';

export const OTA_CLUSTER_ID=0xfc00;
export const OTA_CONFIG_ATTR_ID=0x0001;
export const OTA_MANUFACTURER_CODE=0x1234;
export const OTA_ENDPOINT=10;
export const OTA_ENABLE_CLUSTER_ID=0xfc01;
export const OTA_STATUS_CLUSTER_ID=0xfc02;
export const OTA_CONTROL_ENDPOINT=11;
export const OTA_ENABLE_ATTR_ID=0x0000;
export const OTA_STATUS_ATTR_ID=0x0000;

const OTA_ZIGBEE_WIRE_MAX=100;
const OTA_CONTROL_READBACK_DELAY_MS=120;
const OTA_DIAG_LEN_RE=/^D\|LEN\|(100|[1-9][0-9]?)$/;
const OTA_CHALLENGE_RE=/^A\|[0-9A-Za-z_-]{11}\|[0-9A-Za-z_-]{86}$/;
const OTA_PROVISION_RE=/^P\|[0-9A-Za-z_-]+$/;
const OTA_CHECK_RE=/^C\|[^|]{1,32}\|[0-9A-Za-z]{3}\|[0-9A-Za-z_-]{11}\|[0-9A-Za-z_-]{22}$/;
const OTA_CLUSTER_NAME='jarzemOta', OTA_ATTR_NAME='otaCommand';
const OTA_ENABLE_CLUSTER_NAME='jarzemOtaEnable', OTA_ENABLE_ATTR_NAME='enableOta';
const OTA_STATUS_CLUSTER_NAME='jarzemOtaStatus', OTA_STATUS_ATTR_NAME='otaStatus';
const OTA_CMD_TO_DEVICE='otaToDevice', OTA_CMD_FROM_DEVICE='otaFromDevice';
const OTA_CMD_TO_DEVICE_ID=0x04, OTA_CMD_FROM_DEVICE_ID=0x11;

const OTA_STATUS_BITS=[
    [0x80,'error'], [0x40,'provisioning'], [0x20,'firmware'], [0x10,'verify'],
    [0x08,'skipped'], [0x04,'timeout'], [0x02,'finished'], [0x01,'started'],
];

export const decodeOtaStatus=(value)=>{
    const n=Number(value)&0xff;
    if(n===0)return'idle';
    const parts=OTA_STATUS_BITS.filter(([bit])=>(n&bit)!==0).map(([,name])=>name);
    return parts.length?parts.join('+'):`unknown_0x${n.toString(16).padStart(2,'0')}`;
};

const decodeOtaControlUplink=(payload)=>{
    const match=/^T\|([01])\|([0-9A-Fa-f]{2})$/.exec(payload);
    if(!match)return undefined;
    return{
        enable_ota:match[1]==='1'?'ON':'OFF',
        ota_status:decodeOtaStatus(parseInt(match[2],16)),
    };
};

const b64urlDecode=(s)=>Buffer.from(s.replace(/-/g,'+').replace(/_/g,'/')+'='.repeat((4-s.length%4)%4),'base64');
const delay=(ms)=>new Promise((resolve)=>setTimeout(resolve,ms));
const otaControlEndpoint=(entity,meta)=>meta?.device?.getEndpoint(OTA_CONTROL_ENDPOINT)??(entity?.ID===OTA_CONTROL_ENDPOINT?entity:undefined);

const validateOtaCommand=(value)=>{
    if(typeof value!=='string')throw new Error('OTA command must be a string');
    const bytes=Buffer.byteLength(value,'utf8');
    if(bytes<1||bytes>OTA_ZIGBEE_WIRE_MAX)throw new Error(`OTA MQTT payload must be 1-${OTA_ZIGBEE_WIRE_MAX} bytes`);
    if(value==='D|PING'||value==='D|STOP'||OTA_DIAG_LEN_RE.test(value))return;
    if(value.startsWith('A|')){if(!OTA_CHALLENGE_RE.test(value))throw new Error('Challenge must be A|random|signature');return;}
    if(value.startsWith('P|')){if(!OTA_PROVISION_RE.test(value))throw new Error('Provisioning must be P|AES-GCM-data');return;}
    if(value.startsWith('C|')){if(!OTA_CHECK_RE.test(value))throw new Error('OTA CHECK must be C|version|ABC|random|mac');return;}
    throw new Error('Unsupported OTA command');
};

const otaRadioValue=(value)=>{
    if(value.startsWith('A|')){
        const p=value.split('|');
        const random=b64urlDecode(p[1]),sig=b64urlDecode(p[2]);
        if(random.length!==8||sig.length!==64)throw new Error('Challenge binary length invalid');
        return Buffer.concat([random,sig]);
    }
    if(value.startsWith('P|'))return b64urlDecode(value.slice(2));
    return Buffer.from(value,'utf8');
};

const logOtaUplink=(msg,meta,payload)=>{
    const ieee=msg?.device?.ieeeAddr??meta?.device?.ieeeAddr??'unknown';
    const kind=payload.split('|',1)[0];
    meta?.logger?.info?.(`[OTA/ZIGBEE RX] kind=${kind} from=${ieee} endpoint=${msg?.endpoint?.ID??'?'} cluster=0x${OTA_CLUSTER_ID.toString(16)} bytes=${Buffer.byteLength(payload,'utf8')}`);
};

const otaUplinkState=(msg,meta,payload)=>{
    logOtaUplink(msg,meta,payload);
    const control=decodeOtaControlUplink(payload);
    return control?{...control,ota_transport:payload}:{ota_transport:payload};
};

const fromCommand={cluster:OTA_CLUSTER_NAME,type:['commandOtaFromDevice'],convert:(model,msg,publish,options,meta)=>{
    if(msg.endpoint.ID!==OTA_ENDPOINT)return;
    const value=msg.data?.payload;
    if(value==null)return;
    return otaUplinkState(msg,meta,String(value));
}};

const fromRaw={cluster:OTA_CLUSTER_NAME,type:['raw'],convert:(model,msg,publish,options,meta)=>{
    if(msg.endpoint.ID!==OTA_ENDPOINT)return;
    const raw=Buffer.isBuffer(msg.data)?msg.data:msg.data?.data;
    if(raw==null)return;
    const b=Buffer.isBuffer(raw)?raw:Buffer.from(raw);
    if(b.length<2)return;
    const direct=b.toString('utf8');
    if(/^(H|D|R|F|T)\|/.test(direct))return otaUplinkState(msg,meta,direct);
    if(b.length>=4&&b[2]===OTA_CMD_FROM_DEVICE_ID){
        const n=b[3];
        if(n<1||b.length<4+n)return;
        return otaUplinkState(msg,meta,b.subarray(4,4+n).toString('utf8'));
    }
}};

const fromEnable={cluster:OTA_ENABLE_CLUSTER_NAME,type:['attributeReport','readResponse'],convert:(model,msg)=>{
    if(msg.endpoint.ID!==OTA_CONTROL_ENDPOINT||msg.data?.[OTA_ENABLE_ATTR_NAME]===undefined)return;
    return{enable_ota:msg.data[OTA_ENABLE_ATTR_NAME]?'ON':'OFF'};
}};

const fromStatus={cluster:OTA_STATUS_CLUSTER_NAME,type:['attributeReport','readResponse'],convert:(model,msg)=>{
    if(msg.endpoint.ID!==OTA_CONTROL_ENDPOINT||msg.data?.[OTA_STATUS_ATTR_NAME]===undefined)return;
    return{ota_status:decodeOtaStatus(msg.data[OTA_STATUS_ATTR_NAME])};
}};

const toCommand={key:['ota_command'],convertSet:async(entity,key,value,meta)=>{
    validateOtaCommand(value);
    const endpoint=meta.device.getEndpoint(OTA_ENDPOINT);
    if(!endpoint)throw new Error(`OTA endpoint ${OTA_ENDPOINT} not found on device`);
    const radio=otaRadioValue(value);
    meta?.logger?.info?.(`[OTA/ZIGBEE TX] kind=${value.split('|',1)[0]} endpoint=${OTA_ENDPOINT} cluster=0x${OTA_CLUSTER_ID.toString(16)} mqtt_bytes=${Buffer.byteLength(value,'utf8')} radio_value_bytes=${radio.length}`);
    await endpoint.write(OTA_CLUSTER_NAME,{[OTA_ATTR_NAME]:radio},{manufacturerCode:OTA_MANUFACTURER_CODE});
    return{state:{}};
}};

const toEnable={key:['enable_ota'],convertSet:async(entity,key,value,meta)=>{
    const endpoint=otaControlEndpoint(entity,meta);
    if(!endpoint)throw new Error(`OTA control endpoint ${OTA_CONTROL_ENDPOINT} not found on device; re-interview device`);
    const enabled=String(value).toUpperCase()==='ON'||value===true||value===1;
    await endpoint.write(OTA_ENABLE_CLUSTER_NAME,{[OTA_ENABLE_ATTR_NAME]:enabled},{manufacturerCode:OTA_MANUFACTURER_CODE});
    await delay(OTA_CONTROL_READBACK_DELAY_MS);
    await endpoint.read(OTA_ENABLE_CLUSTER_NAME,[OTA_ENABLE_ATTR_NAME],{manufacturerCode:OTA_MANUFACTURER_CODE});
    await endpoint.read(OTA_STATUS_CLUSTER_NAME,[OTA_STATUS_ATTR_NAME],{manufacturerCode:OTA_MANUFACTURER_CODE});
    return{state:{}};
},convertGet:async(entity,key,meta)=>{
    const endpoint=otaControlEndpoint(entity,meta);
    if(!endpoint)throw new Error(`OTA control endpoint ${OTA_CONTROL_ENDPOINT} not found on device; re-interview device`);
    await endpoint.read(OTA_ENABLE_CLUSTER_NAME,[OTA_ENABLE_ATTR_NAME],{manufacturerCode:OTA_MANUFACTURER_CODE});
}};

const getStatus={key:['ota_status'],convertGet:async(entity,key,meta)=>{
    const endpoint=otaControlEndpoint(entity,meta);
    if(!endpoint)throw new Error(`OTA control endpoint ${OTA_CONTROL_ENDPOINT} not found on device; re-interview device`);
    await endpoint.read(OTA_STATUS_CLUSTER_NAME,[OTA_STATUS_ATTR_NAME],{manufacturerCode:OTA_MANUFACTURER_CODE});
}};

export const extend=[
    m.deviceAddCustomCluster(OTA_CLUSTER_NAME,{name:OTA_CLUSTER_NAME,ID:OTA_CLUSTER_ID,manufacturerCode:OTA_MANUFACTURER_CODE,attributes:{[OTA_ATTR_NAME]:{name:OTA_ATTR_NAME,ID:OTA_CONFIG_ATTR_ID,type:Zcl.DataType.OCTET_STR,write:true}},commands:{[OTA_CMD_TO_DEVICE]:{name:OTA_CMD_TO_DEVICE,ID:OTA_CMD_TO_DEVICE_ID,parameters:[{name:'payload',type:Zcl.DataType.CHAR_STR}]}},commandsResponse:{[OTA_CMD_FROM_DEVICE]:{name:OTA_CMD_FROM_DEVICE,ID:OTA_CMD_FROM_DEVICE_ID,parameters:[{name:'payload',type:Zcl.DataType.CHAR_STR}]}}}),
    m.deviceAddCustomCluster(OTA_ENABLE_CLUSTER_NAME,{name:OTA_ENABLE_CLUSTER_NAME,ID:OTA_ENABLE_CLUSTER_ID,manufacturerCode:OTA_MANUFACTURER_CODE,attributes:{[OTA_ENABLE_ATTR_NAME]:{name:OTA_ENABLE_ATTR_NAME,ID:OTA_ENABLE_ATTR_ID,type:Zcl.DataType.BOOLEAN,write:true}}}),
    m.deviceAddCustomCluster(OTA_STATUS_CLUSTER_NAME,{name:OTA_STATUS_CLUSTER_NAME,ID:OTA_STATUS_CLUSTER_ID,manufacturerCode:OTA_MANUFACTURER_CODE,attributes:{[OTA_STATUS_ATTR_NAME]:{name:OTA_STATUS_ATTR_NAME,ID:OTA_STATUS_ATTR_ID,type:Zcl.DataType.UINT8}}}),
];

export const fromZigbee=[fromCommand,fromRaw,fromEnable,fromStatus];
export const toZigbee=[toCommand,toEnable,getStatus];
export const exposes=[
    e.binary('enable_ota',ea.ALL,'ON','OFF').withCategory('config').withHomeAssistant({enabledByDefault:true}),
    e.text('ota_status',ea.STATE_GET),
];
export const endpointMap={};

export const configure=async(device,coordinatorEndpoint,logger)=>{
    if(!device.getEndpoint(OTA_ENDPOINT))logger?.warn?.(`JarZem OTA endpoint ${OTA_ENDPOINT} not found`);
    const ctl=device.getEndpoint(OTA_CONTROL_ENDPOINT);
    if(!ctl){
        logger?.warn?.(`JarZem OTA control endpoint ${OTA_CONTROL_ENDPOINT} not found; device interview must be refreshed`);
        return;
    }
    await ctl.read(OTA_ENABLE_CLUSTER_NAME,[OTA_ENABLE_ATTR_NAME],{manufacturerCode:OTA_MANUFACTURER_CODE});
    await ctl.read(OTA_STATUS_CLUSTER_NAME,[OTA_STATUS_ATTR_NAME],{manufacturerCode:OTA_MANUFACTURER_CODE});
};
