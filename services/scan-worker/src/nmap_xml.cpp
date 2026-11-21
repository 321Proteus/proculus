#include "nmap_xml.hpp"

#include <expat.h>

#include <cstdlib>
#include <cstring>
#include <stdexcept>

namespace proculus {

namespace {

struct Ctx {
	NmapResult result;
	HostResult host;
	PortResult port;
	bool in_host = false;
	bool in_port = false;
	bool in_cpe = false;
	std::string text;
	XML_Parser parser = nullptr;
	std::string error;
};

const char* attr(const char** atts, const char* name) {
	for (; atts[0]; atts += 2)
		if (std::strcmp(atts[0], name) == 0) return atts[1];
	return "";
}

void start(void* user, const char* name, const char** atts) {
	auto* c = static_cast<Ctx*>(user);
	if (!std::strcmp(name, "nmaprun")) {
		c->result.nmap_version = attr(atts, "version");
	} else if (!std::strcmp(name, "host")) {
		c->host = HostResult{};
		c->in_host = true;
	} else if (c->in_host && !std::strcmp(name, "status")) {
		c->host.state = attr(atts, "state");
		c->host.reason = attr(atts, "reason");
	} else if (c->in_host && !std::strcmp(name, "address")) {
		if (!std::strcmp(attr(atts, "addrtype"), "ipv4"))
			c->host.address = attr(atts, "addr");
	} else if (c->in_host && !std::strcmp(name, "hostname")) {
		c->host.hostnames.emplace_back(attr(atts, "name"));
	} else if (c->in_host && !std::strcmp(name, "port")) {
		c->port = PortResult{};
		c->port.protocol = attr(atts, "protocol");
		c->port.port = static_cast<uint16_t>(
			std::strtoul(attr(atts, "portid"), nullptr, 10));
		c->in_port = true;
	} else if (c->in_port && !std::strcmp(name, "state")) {
		c->port.state = attr(atts, "state");
		c->port.reason = attr(atts, "reason");
	} else if (c->in_port && !std::strcmp(name, "service")) {
		ServiceInfo& s = c->port.service;
		c->port.has_service = true;
		s.name = attr(atts, "name");
		s.product = attr(atts, "product");
		s.version = attr(atts, "version");
		s.extrainfo = attr(atts, "extrainfo");
		s.ostype = attr(atts, "ostype");
		s.devicetype = attr(atts, "devicetype");
		s.method = attr(atts, "method");
		s.tunnel = attr(atts, "tunnel");
		s.confidence = std::atoi(attr(atts, "conf"));
	} else if (c->in_port && !std::strcmp(name, "cpe")) {
		c->in_cpe = true;
		c->text.clear();
	} else if (!c->in_host && !std::strcmp(name, "finished")) {
		c->result.elapsed_seconds = std::atof(attr(atts, "elapsed"));
	} else if (!c->in_host && !std::strcmp(name, "hosts")) {
		c->result.hosts_up = std::atoi(attr(atts, "up"));
		c->result.hosts_down = std::atoi(attr(atts, "down"));
	}
}

void end(void* user, const char* name) {
	auto* c = static_cast<Ctx*>(user);
	if (!std::strcmp(name, "cpe") && c->in_cpe) {
		c->port.service.cpes.push_back(c->text);
		c->in_cpe = false;
	} else if (!std::strcmp(name, "port") && c->in_port) {
		c->host.ports.push_back(std::move(c->port));
		c->in_port = false;
	} else if (!std::strcmp(name, "host") && c->in_host) {
		c->result.hosts.push_back(std::move(c->host));
		c->in_host = false;
	}
}

void chars(void* user, const char* s, int len) {
	auto* c = static_cast<Ctx*>(user);
	if (c->in_cpe) c->text.append(s, static_cast<size_t>(len));
}

void entity_decl(void* user, const XML_Char*, int, const XML_Char*, int,
	const XML_Char*, const XML_Char*, const XML_Char*, const XML_Char*) {
	auto* c = static_cast<Ctx*>(user);
	c->error = "XML entity declarations are not allowed";
	XML_StopParser(c->parser, XML_FALSE);
}

} // namespace

NmapResult parse_nmap_xml(const std::string& xml) {
	Ctx ctx;
	ctx.parser = XML_ParserCreate("UTF-8");
	if (!ctx.parser) throw std::runtime_error("cannot create XML parser");
	XML_SetUserData(ctx.parser, &ctx);
	XML_SetElementHandler(ctx.parser, start, end);
	XML_SetCharacterDataHandler(ctx.parser, chars);
	XML_SetEntityDeclHandler(ctx.parser, entity_decl);

	XML_Status st = XML_Parse(
		ctx.parser, xml.data(), static_cast<int>(xml.size()), XML_TRUE);
	std::string msg;
	if (st == XML_STATUS_ERROR) {
		msg = !ctx.error.empty() ? ctx.error
								 : std::string("malformed nmap XML: ") +
				XML_ErrorString(XML_GetErrorCode(ctx.parser));
	}
	XML_ParserFree(ctx.parser);
	if (!msg.empty()) throw std::runtime_error(msg);
	return std::move(ctx.result);
}

} // namespace proculus
