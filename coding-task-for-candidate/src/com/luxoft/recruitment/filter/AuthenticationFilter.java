package com.luxoft.recruitment.filter;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Properties;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.annotation.WebFilter;
import javax.servlet.http.HttpServletResponse;

/**
 * Servlet Filter implementation class AuthenticationFilter
 */
@WebFilter("/AuthenticationFilter")
public class AuthenticationFilter implements Filter {

	private static List<String> blockledIps = new ArrayList<String>();	

	public AuthenticationFilter() {
	}

	public void destroy() {
		System.out.println("destroy method is called in " + this.getClass().getName());
	}

	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		System.out.println("doFilter method is called in " + this.getClass().getName());

		readProperties();
		
		String ipAddress = request.getRemoteAddr();
				
		if(blockledIps.contains(ipAddress)){
			System.out.println("User logged in " + ipAddress + " at " + new Date().toString());
			chain.doFilter(request, response);
		} else {
			HttpServletResponse httpResponse = null;
			if (response instanceof HttpServletResponse) {
				httpResponse = (HttpServletResponse) response;
			}
			httpResponse.sendError(HttpServletResponse.SC_FORBIDDEN, "This Page Requires Authentication.");
		}

	}

	public void init(FilterConfig fConfig) throws ServletException {
		System.out.println("init method is called in " + this.getClass().getName());
	}

	public static void readProperties() {
		Properties props = new Properties();
		try {
			
			blockledIps.clear();
			InputStream inputStream = Thread.currentThread().getContextClassLoader()
					.getResourceAsStream("firewall.properties");
			if (inputStream != null) {
				props.load(inputStream);
				String ipList = props.getProperty("blocked.ips");				
				String[] ipp = ipList.split(",");
				
				for(String ip : ipp)
				AuthenticationFilter.blockledIps.add(ip);					
			}
		} catch (Exception ex) {
			System.out.println(ex.getMessage());
		}

	}

}
