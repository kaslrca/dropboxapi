package controller;

import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

import javax.servlet.http.HttpSession;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;

import com.dropbox.core.DbxAppInfo;
import com.dropbox.core.DbxAuthFinish;
import com.dropbox.core.DbxClient;
import com.dropbox.core.DbxException;
import com.dropbox.core.DbxRequestConfig;
import com.dropbox.core.DbxStandardSessionStore;
import com.dropbox.core.DbxWebAuth;
import com.dropbox.core.DbxWebAuth.BadRequestException;
import com.dropbox.core.DbxWebAuth.BadStateException;
import com.dropbox.core.DbxWebAuth.CsrfException;
import com.dropbox.core.DbxWebAuth.NotApprovedException;
import com.dropbox.core.DbxWebAuth.ProviderException;

@Controller
@RequestMapping("/api")
public class ApiController {
    private static Logger log = LoggerFactory.getLogger(ApiController.class);

    static final String APP_KEY = "hs1dvk9ib56vnga";
    static final String APP_SECRET = "ep4gexd8wslqmtw";
    static final String AUTH_URI_WITH_HTTPS = "https://10.1.100.76:8443/dropboxapi/api/https/authorization";
    static final String AUTH_URI_WITH_HTTP = "http://localhost:8080/dropboxapi/api/http/authorization";

    @RequestMapping(value = "/http/auth", method = RequestMethod.GET)
    public String nonauth(HttpSession session) throws InterruptedException {

        DbxAppInfo appInfo = new DbxAppInfo(APP_KEY, APP_SECRET);
        DbxRequestConfig config = new DbxRequestConfig("JavaTutorial/1.0", Locale.getDefault().toString());
        DbxWebAuth webAuth = new DbxWebAuth(config, appInfo, AUTH_URI_WITH_HTTP, new DbxStandardSessionStore(session,
                "csrf"));

        String authorizeUrl = webAuth.start();

        return "redirect:" + authorizeUrl;
    }

    @RequestMapping(value = "/http/authorization", method = RequestMethod.GET, params = { "state", "code" })
    public String nonauthorization(@RequestParam(value = "state") String state,
            @RequestParam(value = "code") String code, HttpSession session, Model model) {

        DbxAppInfo appInfo = new DbxAppInfo(APP_KEY, APP_SECRET);
        DbxRequestConfig config = new DbxRequestConfig("JavaTutorial/1.0", Locale.getDefault().toString());
        DbxWebAuth webAuth = new DbxWebAuth(config, appInfo, AUTH_URI_WITH_HTTP, new DbxStandardSessionStore(session,
                "csrf"));

        Map<String, String[]> queryParams = new HashMap<String, String[]>();
        queryParams.put("state", new String[] { state });
        queryParams.put("code", new String[] { code });
        DbxAuthFinish authFinish;

        try {
            authFinish = webAuth.finish(queryParams);
            String accessToken = authFinish.accessToken;

            DbxClient client = new DbxClient(config, accessToken);

            model.addAttribute("client", client);
            model.addAttribute("token", accessToken);
        } catch (DbxException | BadRequestException | BadStateException | CsrfException | NotApprovedException
                | ProviderException e) {
            e.printStackTrace();
        }

        return "userInfo";
    }


    @RequestMapping(value = "/https/auth", method = RequestMethod.GET)
    public String auth(HttpSession session) throws InterruptedException {
       
        DbxAppInfo appInfo = new DbxAppInfo(APP_KEY, APP_SECRET);
        DbxRequestConfig config = new DbxRequestConfig("JavaTutorial/1.0", Locale.getDefault().toString());
        DbxWebAuth webAuth = new DbxWebAuth(config, appInfo, AUTH_URI_WITH_HTTPS, new DbxStandardSessionStore(session,
                "csrf"));

        String authorizeUrl = webAuth.start();

        return "redirect:" + authorizeUrl;
    }

    @RequestMapping(value = "/https/auth/reapprove/{value}", method = RequestMethod.GET)
    public String authReapprove(@PathVariable String value, HttpSession session) throws InterruptedException {

        DbxAppInfo appInfo = new DbxAppInfo(APP_KEY, APP_SECRET);
        DbxRequestConfig config = new DbxRequestConfig("JavaTutorial/1.0", Locale.getDefault().toString());
        DbxWebAuth webAuth = new DbxWebAuth(config, appInfo, AUTH_URI_WITH_HTTPS, new DbxStandardSessionStore(session,
                "csrf"));

        String authorizeUrl = webAuth.start();

        return "redirect:" + authorizeUrl + "&force_reapprove=" + value;
    }

    @RequestMapping(value = "/https/authorization", method = RequestMethod.GET, params = { "state", "code" })
    public String authorization(@RequestParam(value = "state") String state, @RequestParam(value = "code") String code,
            HttpSession session, Model model) {
        
        DbxAppInfo appInfo = new DbxAppInfo(APP_KEY, APP_SECRET);
        DbxRequestConfig config = new DbxRequestConfig("JavaTutorial/1.0", Locale.getDefault().toString());
        DbxWebAuth webAuth = new DbxWebAuth(config, appInfo, AUTH_URI_WITH_HTTPS, new DbxStandardSessionStore(session,
                "csrf"));
        
        Map<String, String[]> queryParams = new HashMap<String, String[]>();
        queryParams.put("state", new String[] { state });
        queryParams.put("code", new String[] { code });
        DbxAuthFinish authFinish;
        
        try {
            authFinish = webAuth.finish(queryParams);
            String accessToken = authFinish.accessToken;

            DbxClient client = new DbxClient(config, accessToken);

            model.addAttribute("client", client);
            model.addAttribute("token", accessToken);
        } catch (DbxException | BadRequestException | BadStateException | CsrfException | NotApprovedException
                | ProviderException e) {
            e.printStackTrace();
        }
        
        return "userInfo";
    }

}
