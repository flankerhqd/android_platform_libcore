package dalvik.system;

import java.io.FileDescriptor;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.text.SimpleDateFormat;
import org.json.JSONException;
import org.json.JSONStringer;

public final class TaintLog {

    public static final int FS_READ_ACTION           = 0x00000001;
    public static final int FS_READ_DIRECT_ACTION    = 0x00000002;
    public static final int FS_READV_ACTION          = 0x00000004;
    public static final int FS_WRITE_ACTION          = 0x00000008;
    public static final int FS_WRITE_DIRECT_ACTION   = 0x00000010;
    public static final int FS_WRITEV_ACTION         = 0x00000020;

    public static final int NET_READ_ACTION          = 0x00000100;
    public static final int NET_READ_DIRECT_ACTION   = 0x00000200;
    public static final int NET_RECV_ACTION          = 0x00000400;
    public static final int NET_RECV_DIRECT_ACTION   = 0x00000800;
    public static final int NET_SEND_ACTION          = 0x00001000;
    public static final int NET_SEND_DIRECT_ACTION   = 0x00002000;
    public static final int NET_SEND_URGENT_ACTION   = 0x00004000;
    public static final int NET_WRITE_ACTION         = 0x00008000;
    public static final int NET_WRITE_DIRECT_ACTION  = 0x00010000;

    public static final int SSL_READ_ACTION          = 0x00020000;
    public static final int SSL_WRITE_ACTION         = 0x00040000;

    public static final int SMS_ACTION               = 0x00100000; 
    public static final int SMS_MULTIPART_ACTION     = 0x00200000; 
    public static final int SMS_DATA_ACTION          = 0x00400000;

    public static final int CIPHER_ACTION            = 0x00800000;
    public static final int ERROR_ACTION             = 0x01000000;
    public static final int CALL_ACTION              = 0x02000000;

    private static String GLOBAL_ACTIVE_KEY          = "tdroid.global.active";
    private static String GLOBAL_SKIP_LOOKUP_KEY     = "tdroid.global.skiplookup";
    private static String GLOBAL_ACTION_MASK_KEY     = "tdroid.global.actionmask";
    private static String GLOBAL_TAINT_MASK_KEY      = "tdroid.global.taintmask";    
    
    private static String FS_LOG_TIMESTAMP_KEY       = "tdroid.fs.logtimestamp";
    private static String FS_READ_TAINT_MASK_KEY     = "tdroid.fs.read.taintmask";
    private static String FS_WRITE_TAINT_MASK_KEY    = "tdroid.fs.write.taintmask";

    private static TaintLog itsInstance;

    private boolean itsGlobalActiveFlag = false;
    private boolean itsGlobalSkipLookupPropsFlag = false;
    private int itsGlobalActionMask = 0xFFFFFFFF;
    private int itsGlobalTaintMask = 0xFFFFFFFF;

    private boolean itsFSLogTimestampFlag = false;
    private int itsFSReadTaintMask = 0x00FFFFFF;
    private int itsFSWriteTaintMask = 0x00FFFFFF;

    private TaintLog() 
    {
        readProperties();
        printProperties();
    }

    public static TaintLog getInstance()
    {
        if (itsInstance == null)
        {
            itsInstance = new TaintLog();
        }
        return itsInstance;
    }

    private void readProperties()
    {
        if (!itsGlobalSkipLookupPropsFlag)
        {
            boolean aBeforeGlobalActiveFlag = itsGlobalActiveFlag;
            boolean aBeforeGlobalSkipLookupPropsFlag = itsGlobalSkipLookupPropsFlag;
            int aBeforeGlobalActionMask = itsGlobalActionMask;
            int aBeforeGlobalTaintMask = itsGlobalTaintMask;
            boolean aBeforeFSLogTimestampFlag = itsFSLogTimestampFlag;
            int aBeforeFSReadTaintMask = itsFSReadTaintMask;
            int aBeforeFSWriteTaintMask = itsFSWriteTaintMask;

            itsGlobalActiveFlag = getPropertyAsBool(GLOBAL_ACTIVE_KEY, false);
            itsGlobalSkipLookupPropsFlag = getPropertyAsBool(GLOBAL_SKIP_LOOKUP_KEY, false);
            itsGlobalActionMask = getPropertyAsInt(GLOBAL_ACTION_MASK_KEY, 0xFFFFFFFF);
            itsGlobalTaintMask = getPropertyAsInt(GLOBAL_TAINT_MASK_KEY, 0xFFFFFFFF);
            itsFSLogTimestampFlag = getPropertyAsBool(FS_LOG_TIMESTAMP_KEY, false);
            itsFSReadTaintMask = getPropertyAsInt(FS_READ_TAINT_MASK_KEY, 0x00FFFFFF);
            itsFSWriteTaintMask = getPropertyAsInt(FS_WRITE_TAINT_MASK_KEY, 0x00FFFFFF);

            if (aBeforeGlobalActiveFlag != itsGlobalActiveFlag ||
                aBeforeGlobalSkipLookupPropsFlag != itsGlobalSkipLookupPropsFlag ||
                aBeforeGlobalActionMask != itsGlobalActionMask ||
                aBeforeGlobalTaintMask != itsGlobalTaintMask ||
                aBeforeFSLogTimestampFlag != itsFSLogTimestampFlag ||
                aBeforeFSReadTaintMask != itsFSReadTaintMask ||
                aBeforeFSWriteTaintMask != itsFSWriteTaintMask)
            {
                printProperties();
            }
        }
    }

    private void printProperties()
    {
        StringBuffer aLogStr = new StringBuffer();
        aLogStr.append("TaintLogProperties: itsGlobalActiveFlag=");
        if (itsGlobalActiveFlag)
        {
            aLogStr.append("true");
        }
        else
        {
            aLogStr.append("false");
        }
        aLogStr.append(", itsGlobalSkipLookupPropsFlag=");
        if (itsGlobalSkipLookupPropsFlag)
        {
            aLogStr.append("true");
        }
        else
        {
            aLogStr.append("false");
        }
        aLogStr.append(", itsGlobalActionMask=").append(itsGlobalActionMask);
        aLogStr.append(", itsGlobalTaintMask=").append(itsGlobalTaintMask);
        aLogStr.append(", itsFSLogTimestampFlag=");
        if (itsFSLogTimestampFlag)
        {
            aLogStr.append("true");
        }
        else
        {
            aLogStr.append("false");
        }
        aLogStr.append(", itsFSReadTaintMask=").append(itsFSReadTaintMask);
        aLogStr.append(", itsFSWriteTaintMask=").append(itsFSWriteTaintMask);
        String aLogString = new String(aLogStr);
        log(aLogString);
    }

    /**
     * Logging utility accessible from places android.util.Log
     * is not.
     *
     * @param msg
     *	    the message to log
     */
    native private static void log(String msg);

    /**
     * Return path for a file descriptor
     *
     * @param fd
     *	    the file descriptor
     */
    native private static String getPathFromFd(int fd);

    /**
     * Logging utiltity to obtain the peer IP addr for a file descriptor
     *
     * @param fd
     *	    the file descriptor
     */
    native private static void logPeerFromFd(int fd);

    /**
     * Returns system property
     *
     * @param theKey
     *	    property key
     */
    native private static String getProperty(String theKey, String theDefaultValue);

    /**
     * Returns system property
     *
     * @param theKey
     *	    property key
     */
    native private static int getPropertyAsInt(String theKey, int theDefaultValue);

    /**
     * Returns system property
     *
     * @param theKey
     *	    property key
     */
    native private static boolean getPropertyAsBool(String theKey, boolean theDefaultValue);

    
    /**
     * Logging utility to log outgoing call within android.
     *
     * @param theDialString
     *	    the number to dial
     */
    public void logCallAction(String theDialString)
    {
        readProperties();
        if (itsGlobalActiveFlag && ((CALL_ACTION & itsGlobalActionMask) == CALL_ACTION))
        {
            int aTag = Taint.getTaintString(theDialString);
            if ((0xFFFFFFFF == itsGlobalTaintMask) || 
                (aTag != 0 && (aTag & itsGlobalTaintMask) == aTag))
            {
                String aTagStr = "0x" + Integer.toHexString(aTag);
                String aStackTraceStr = getStackTrace();
                String aTimestamp = getTimestamp();
                String aLogStr = ""; 
                try
                    {
                        aLogStr = new JSONStringer()
                            .array()
                            .object()
                            .key("__CallActionLogEntry__")
                            .value("true")
                            .key("dialString")
                            .value(theDialString)
                            .key("tag")
                            .value(aTagStr)
                            .key("stackTraceStr")
                            .value(aStackTraceStr)
                            .key("timestamp")
                            .value(aTimestamp)
                            .endObject()
                            .endArray()
                            .toString();
                    }
                catch (JSONException ex) 
                    {            
                        log("JSON Exception thrown: " + ex.toString());
                        aLogStr = "[{\"__CallActionLogEntry__\" : \"true"
                            + "\", \"dialString\": \"" + escapeJson(theDialString)
                            + "\", \"tag\": \"" + aTagStr
                            + "\", \"stackTraceStr\": \"" + escapeJson(aStackTraceStr) 
                            + "\", \"timestamp\": \"" + aTimestamp + "\"}]";
                    }
                log(aLogStr);
            }
        }
    }

    /**
     * Logging utility to log cipher usage within android.
     *
     * @param theAction
     *	    the cipher action: init, update, or doFinal
     * @param theId
     *      unique id for the cipher action
     * @param theMode
     *      decryption (2) or encryption (1)
     * @param theInput
     *      input byte stream
     * @param theOutput
     *      output byte stream
     */
    public void logCipherUsage(String theAction, int theId, int theMode, byte[] theInput, byte[] theOutput)
    {
        readProperties();
        if (itsGlobalActiveFlag && ((CIPHER_ACTION & itsGlobalActionMask) == CIPHER_ACTION))
        {
            int aTag = Taint.getTaintByteArray(theInput);
            if ((0xFFFFFFFF == itsGlobalTaintMask) || (aTag != 0 && (aTag & itsGlobalTaintMask) == aTag))
            {
                String aLogStr = "";        
                String aTagStr = "0x" + Integer.toHexString(aTag);
                String aInputStr = "";
                if (theInput != null)
                {
                    aInputStr = new String(theInput);
                }
                String aOutputStr = "";
                if (theOutput != null)
                {
                    aOutputStr = new String(theOutput);
                }
                String aStackTraceStr = "";
                String aTimestamp = "";
                if (theAction == "init" || theAction == "doFinal")
                {
                    aStackTraceStr = getStackTrace();
                    aTimestamp = getTimestamp();
                }
                try
                {
                    aLogStr = new JSONStringer()
                        .array()
                        .object()
                        .key("__CipherUsageLogEntry__")
                        .value("true")
                        .key("action")
                        .value(theAction)
                        .key("id")
                        .value(theId)
                        .key("mode")
                        .value(theMode)
                        .key("tag")
                        .value(aTagStr)
                        .key("input")
                        .value(aInputStr)
                        .key("output")
                        .value(aOutputStr)
                        .key("stackTraceStr")
                        .value(aStackTraceStr)
                        .key("timestamp")
                        .value(aTimestamp)
                        .endObject()
                        .endArray()
                        .toString();
                } 
                catch (JSONException ex) 
                {            
                    log("JSON Exception thrown: " + ex.toString());
                    String aIdStr = Integer.toString(theId);
                    String aModeStr = Integer.toString(theMode);
                    aLogStr = "[{\"__CipherUsageLogEntry__\" : \"true"
                        + "\", \"action\" : \"" + theAction
                        + "\", \"id\": " + aIdStr
                        + ", \"mode\": " + aModeStr
                        + ", \"tag\": \"" + aTagStr 
                        + "\", \"input\": \"" + escapeJson(aInputStr)
                        + "\", \"output\": \"" + escapeJson(aOutputStr)
                        + "\", \"stackTraceStr\": \"" + escapeJson(aStackTraceStr) 
                        + "\", \"timestamp\": \"" + aTimestamp + "\"}]";
                }
                log(aLogStr);
            }
        }
    }    

    public void logError(String theMessage)
    {
        readProperties();
        if (itsGlobalActiveFlag)
        {
            if ((ERROR_ACTION & itsGlobalActionMask) == ERROR_ACTION)
            {
                String aStackTraceStr = getStackTrace();
                String aTimestamp = getTimestamp();
                String aLogStr = "";        
                try
                {
                    aLogStr = new JSONStringer()
                        .array()
                        .object()
                        .key("__ErrorLogEntry__")
                        .value("true")
                        .key("message")
                        .value(theMessage)   
                        .key("stackTraceStr")
                        .value(aStackTraceStr)
                        .key("timestamp")
                        .value(aTimestamp)
                        .endObject()
                        .endArray()
                        .toString();
                } 
                catch (JSONException ex) 
                {            
                    log("JSON Exception thrown: " + ex.toString());
                    aLogStr = "[{\"__ErrorLogEntry__\" : \"true"
                        + "\", \"message\" : \"" + theMessage
                        + "\", \"stackTraceStr\": \"" + escapeJson(aStackTraceStr) 
                        + "\", \"timestamp\": \"" + aTimestamp + "\"}]";
                }
                log(aLogStr);
            }
        }
    }

    /**
     * Logging utiltity for OS file system actions
     *
     * @param theAction
     *	    file system action, e.g. read or write
     * @param theTag
     *      taint tag value
     * @param theFileDescriptor
     *      file descriptor id
     * @param theData
     *      hdata written or read
     */
    public void logFileSystem(int theAction, int theTag, int theFileDescriptor, int theId, String theData)
    {
        readProperties();
        if (itsGlobalActiveFlag && 
            ((theAction & itsGlobalActionMask) == theAction))
        {
            int aTaintMask = 0;
            if (theAction == 0x00000001 ||
                theAction == 0x00000002 ||
                theAction == 0x00000004)
            {
                aTaintMask = itsFSReadTaintMask;                
            }
            else
            {
                aTaintMask = itsFSWriteTaintMask;
            }
            
            if ((0xFFFFFFFF == aTaintMask) || (theTag != 0 && (theTag & aTaintMask) == theTag))
            {                    
                String aLogStr = "";
                String aTagStr = "0x" + Integer.toHexString(theTag);
                String aPath = getPathFromFd(theFileDescriptor);
                String aStackTraceStr = getStackTrace();
                String aTimestamp = "";
                if (itsFSLogTimestampFlag)
                {
                    aTimestamp = getTimestamp();
                }

                try
                {                
                    aLogStr = new JSONStringer()
                        .array()
                        .object()
                        .key("__FileSystemLogEntry__")
                        .value("true")
                        .key("action")
                        .value(theAction)
                        .key("tag")
                        .value(aTagStr)
                        .key("fileDescriptor")
                        .value(theFileDescriptor)
                        .key("filePath")
                        .value(aPath)
                        .key("taintLogId")
                        .value(theId)
                        .key("data")
                        .value(theData)                        
                        .key("stackTraceStr")
                        .value(aStackTraceStr)
                        .key("timestamp")
                        .value(aTimestamp)
                        .endObject()
                        .endArray()
                        .toString();
                } 
                catch (JSONException ex) 
                {
                    log("JSON Exception thrown: " + ex.toString());
                    String aActionStr = Integer.toString(theAction);
                    String aFileDescriptorString = Integer.toString(theFileDescriptor);                
                    String aIdString = Integer.toString(theId);
                    aLogStr = "[{\"__FileSystemLogEntry__\" : \"true"
                        + "\", \"action\" : " + aActionStr
                        + ", \"tag\": \"" + aTagStr 
                        + "\", \"fileDescriptor\": " + aFileDescriptorString
                        + ", \"filePath\": \"" + escapeJson(theData) 
                        + "\", \"taintLogId\": " + aIdString 
                        + ", \"data\": \"" + escapeJson(aPath)                         
                        + "\", \"stackTraceStr\": \"" + escapeJson(aStackTraceStr)
                        + "\", \"timestamp\": \"" + aTimestamp + "\"}]";
                }
        
                log(aLogStr);
            }
        }
    }

    /**
     * Logging utiltity for OS network actions
     *
     * @param theAction
     *	    network action, e.g. send or recv
     * @param theTag
     *      taint tag value
     * @param theDestination
     *      destination address
     * @param thePort
     *      destination port
     * @param theData
     *      data send or received
     */
    public void logNetworkAction(int theAction, int theTag, String theDestination, int thePort, int theId, String theData)
    {
        readProperties();
        if (itsGlobalActiveFlag && 
            ((theAction & itsGlobalActionMask) == theAction) &&
            ((0xFFFFFFFF == itsGlobalTaintMask) || (theTag != 0 && (theTag & itsGlobalTaintMask) == theTag)))
        {
            String aLogStr = "";
            String aTagStr = "0x" + Integer.toHexString(theTag);
            String aStackTraceStr = getStackTrace();
            String aTimestamp = getTimestamp();

            try
            {
                aLogStr = new JSONStringer()
                    .array()
                    .object()
                    .key("__NetworkSendLogEntry__")
                    .value("true")
                    .key("action")
                    .value(theAction)
                    .key("tag")
                    .value(aTagStr)
                    .key("destination")
                    .value(theDestination)
                    .key("port")
                    .value(thePort)
                    .key("taintLogId")
                    .value(theId)
                    .key("data")
                    .value(theData)
                    .key("stackTraceStr")
                    .value(aStackTraceStr)
                    .key("timestamp")
                    .value(aTimestamp)
                    .endObject()
                    .endArray()
                    .toString();
            } 
            catch (JSONException ex) 
            {            
                log("JSON Exception thrown: " + ex.toString());
                String aActionStr = Integer.toString(theAction);
                String aPortStr = Integer.toString(thePort);
                String aIdString = Integer.toString(theId);
                aLogStr = "[{\"__NetworkSendLogEntry__\" : \"true"
                    + "\", \"action : " + aActionStr
                    + ", \"tag\": \"" + aTagStr 
                    + "\", \"destination\": \"" + theDestination 
                    + "\", \"port\": " + aPortStr 
                    + "\", \"taintLogId\": " + aIdString 
                    + ", \"data\": \"" + escapeJson(theData)
                    + "\", \"stackTraceStr\": \"" + escapeJson(aStackTraceStr)
                    + "\", \"timestamp\": \"" + aTimestamp + "\"}]";
            }
            log(aLogStr);
        }
    }

    public void logSSL(int theAction, int theTag, FileDescriptor theDestination, String theData)
    {
        readProperties();
        if (itsGlobalActiveFlag && 
            ((theAction & itsGlobalActionMask) == theAction) &&
            ((0xFFFFFFFF == itsGlobalTaintMask) || (theTag != 0 && (theTag & itsGlobalTaintMask) == theTag)))
        {
            String aLogStr = "";
            String aTagStr = "0x" + Integer.toHexString(theTag);
            String aDestination = (theDestination.hasName) ? theDestination.name : "unknown";
            String aStackTraceStr = getStackTrace();
            String aTimestamp = getTimestamp();
            
            try
            {
                aLogStr = new JSONStringer()
                    .array()
                    .object()
                    .key("__SSLLogEntry__")
                    .value("true")
                    .key("action")
                    .value(theAction)
                    .key("tag")
                    .value(aTagStr)
                    .key("destination")
                    .value(aDestination)
                    .key("port")
                    .value(theDestination.port)
                    .key("data")
                    .value(theData)
                    .key("stackTraceStr")
                    .value(aStackTraceStr)
                    .key("timestamp")
                    .value(aTimestamp)
                    .endObject()
                    .endArray()
                    .toString();
            } 
            catch (JSONException ex) 
            {            
                log("JSON Exception thrown: " + ex.toString());
                String aActionStr = Integer.toString(theAction);
                String aPortStr = Integer.toString(theDestination.port);
                aLogStr = "[{\"__SSLLogEntry__\" : \"true"
                    + "\", \"action\" : " + aActionStr
                    + ", \"tag\": \"" + aTagStr 
                    + "\", \"destination\": \"" + aDestination 
                    + "\", \"port\": " + aPortStr 
                    + ", \"data\": \"" + escapeJson(theData)
                    + "\", \"stackTraceStr\": \"" + escapeJson(aStackTraceStr)
                    + "\", \"timestamp\": \"" + aTimestamp + "\"}]";
            }
            log(aLogStr);
        }
    }

    /**
     * Logging utiltity for SMS actions
     *
     * @param theAction
     *	    SMS action, e.g. sendSms or sendDataMessage
     * @param theDestination
     *      destination phone number
     * @param theText
     *      text to be sent
     */
    public void logSmsAction(int theAction, String theDestination, String theScAddress, String theText)
    {
        readProperties();
        if (itsGlobalActiveFlag && ((theAction & itsGlobalActionMask) == theAction))
        {
            int aTextTag = Taint.getTaintString(theText);
            int aDestinationTag = Taint.getTaintString(theDestination);
            if ((0xFFFFFFFF == itsGlobalTaintMask) || 
                (aTextTag != 0 && (aTextTag & itsGlobalTaintMask) == aTextTag) ||
                (aDestinationTag != 0 && (aDestinationTag & itsGlobalTaintMask) == aDestinationTag))
            {
                String aLogStr = "";        
                String aTextTagStr = "0x" + Integer.toHexString(aTextTag);
                String aDestinationTagStr = "0x" + Integer.toHexString(aDestinationTag);
                String aStackTraceStr = getStackTrace();
                String aTimestamp = getTimestamp();
                
                try
                {
                    aLogStr = new JSONStringer()
                        .array()
                        .object()
                        .key("__SendSmsLogEntry__")
                        .value("true")
                        .key("action")
                        .value(theAction)
                        .key("tag")
                        .value(aTextTagStr)
                        .key("destination")
                        .value(theDestination)
                        .key("destinationTag")
                        .value(aDestinationTagStr)
                        .key("scAddress")
                        .value(theScAddress)
                        .key("text")
                        .value(theText)
                        .key("stackTraceStr")
                        .value(aStackTraceStr)
                        .key("timestamp")
                        .value(aTimestamp)
                        .endObject()
                        .endArray()
                        .toString();
                } 
                catch (JSONException ex) 
                {            
                    log("JSON Exception thrown: " + ex.toString());
                    String aActionStr = Integer.toString(theAction);
                    aLogStr = "[{\"__SendSmsLogEntry__\" : \"true"
                        + "\", \"action\" : " + aActionStr
                        + ", \"tag\": \"" + aTextTagStr 
                        + "\", \"destination\": \"" + theDestination 
                        + "\", \"destinationTag\": \"" + aDestinationTagStr
                        + "\", \"scAddress\": \"" + theScAddress
                        + "\", \"text\": \"" + escapeJson(theText)
                        + "\", \"stackTraceStr\": \"" + escapeJson(aStackTraceStr)
                        + "\", \"timestamp\": \"" + aTimestamp + "\"}]";
                }
                log(aLogStr);
            }
        }
    }

    /**
     * Logging utiltity for sending multipart SMS
     *
     * @param theDestination
     *      destination phone number
     * @param theTextParts
     *      text parts to be sent
     */
    public void logSendMultipartSms(String theDestination, String theScAddress, ArrayList<String> theTextParts)
    {
        String aText = "";
        for (String aTextPart : theTextParts)
        {
            aText += aTextPart;
        }
        logSmsAction(SMS_MULTIPART_ACTION, theDestination, theScAddress, aText);
    }

    /**
     * Logging utiltity for sending data SMS
     *
     * @param theDestination
     *      destination phone number
     * @param thePort
     *      destination phone port
     * @param theData
     *      data to be sent
     */
    public  void logSendDataMessage(String theDestination, String theScAddress, int thePort, byte[] theData)
    {
        String aPortStr = Integer.toString(thePort);
        String aDestination = theDestination + ":" + aPortStr;
        String aText = new String(theData);
        logSmsAction(SMS_DATA_ACTION, aDestination, theScAddress, aText);
    }
    
    private String getStackTrace()
    {
        String aStackTraceStr = "";
        StackTraceElement[] aStackTraceElementVec = Thread.currentThread().getStackTrace();
        for (int i = 0 ; i < aStackTraceElementVec.length; i++)
        {
            StackTraceElement aStackTraceElement = aStackTraceElementVec[i];
            String aClassname = aStackTraceElement.getClassName();
            String aMethodName = aStackTraceElement.getMethodName();
            int aLineNumber = aStackTraceElement.getLineNumber();
            aStackTraceStr += aClassname + "," + aMethodName + ":" + aLineNumber + "||";
        }

        return aStackTraceStr;
    }

    private String getTimestamp()
    {
        String aTimestamp = "";
        try
        {
            SimpleDateFormat aDateFormat = new SimpleDateFormat("yyyyMMddHHmmss");
            aTimestamp = aDateFormat.format(new Date(System.currentTimeMillis()));
        }
        catch (Exception e)
        {
            // Do nothing
        }
        return aTimestamp;
    }

    private String escapeJson(String theString)
    {
        if (theString == null)
        {
            return null;
        }
        StringBuffer aStringBuf = new StringBuffer();

        for (int i = 0; i < theString.length(); i++)
        {
            char aChar = theString.charAt(i);
            switch(aChar)
            {
            case '"':
            case '\\':
            case '/':
                aStringBuf.append("\\").append(aChar);
                break;
            case '\b':
                aStringBuf.append("\\b");
                break;
            case '\f':
                aStringBuf.append("\\f");
                break;
            case '\n':
                aStringBuf.append("\\n");
                break;
            case '\r':
                aStringBuf.append("\\r");
                break;
            case '\t':
                aStringBuf.append("\\t");
                break;
            default:
                if (aChar >= 0x00 && aChar <= 0x1F)
                {
                    aStringBuf.append(String.format("\\u%04x", (int)aChar));
                }
                else
                {
                    aStringBuf.append(aChar);
                }
                break;
            }
        }
        
        return aStringBuf.toString(); 
    }
}