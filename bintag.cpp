/*
 * =====================================================================================
 *
 *       Filename:  bintag.cpp
 *
 *    Description:  BinTag IDA Pro Plugin
 *
 *        Version:  1.0
 *        Created:  07/08/2019 10:26:20 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  alexander.rausch@dcso.de
 *   Organization:  DCSO Deutsche Cyber-Sicherheitsorganisation GmbH
 *
 * =====================================================================================
 */

/*
 * =====================================================================================
 * 3rd party includes
 * =====================================================================================
 */

#include "nlohmann/json.hpp"

/*
 * =====================================================================================
 * ida api includes
 * =====================================================================================
 */

#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <nalt.hpp>
#include <kernwin.hpp>
#include <auto.hpp>
#include <funcs.hpp>
#include <range.hpp>
#include <ua.hpp>
#include <typeinf.hpp>
#include <pro.h>

/*
 * =====================================================================================
 * stl includes
 * =====================================================================================
 */

#define _USE_MATH_DEFINES

#include <algorithm>
#include <cmath>
#include <exception>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <list>
#include <sstream>
#include <string>
#include <tuple>

//for backwards compatibility with IDA SDKs < 7.3
#include "compat.h"

/*
 * =====================================================================================
 * namespaces
 * =====================================================================================
 */

namespace fs = std::filesystem;

using json = nlohmann::json;

/*
 * =====================================================================================
 * defines
 * =====================================================================================
 */

#ifndef VERSION
#define VERSION "1.0"
#endif
#define ADD_TAG_ACTION_NAME "bintag::AddTag"
#define ADD_TAG_ACTION_LABEL "Add BinTag"

/*
 * =====================================================================================
 * static constants
 * =====================================================================================
 */

static const char help[] = "BinTag " VERSION;
static const char comment[] = "BinTag tagging plugin";
static const char wanted_name[] = "BinTag";
static const char wanted_hotkey[] = "";

// basedir relative to $HOME
constexpr char bintag_basedir[] = ".bintag";

/*
 * =====================================================================================
 * function declarations
 * =====================================================================================
 */

int idaapi init(void);
void idaapi term(void);
bool idaapi run(size_t);
bool idaapi add_tag();

/*
 * =====================================================================================
 * struct and datatype definitions
 * =====================================================================================
 */

struct add_tag_ah_t : public action_handler_t {
    virtual int idaapi activate(action_activation_ctx_t *) {
        add_tag();
        return 0;
    }

    virtual action_state_t idaapi update(action_update_ctx_t *) {
        return AST_ENABLE_ALWAYS;
    }
};

struct bintag_info_t {
    TWidget *cv;
    strvec_t sv;
    bintag_info_t() : cv(NULL) {}
};

/*
 * =====================================================================================
 * static variables
 * =====================================================================================
 */

static const bintag_info_t *last_si = NULL;
static add_tag_ah_t add_tag_ah;

/*
 * =====================================================================================
 * filesystem related functions
 * =====================================================================================
 */

static fs::path get_config_dir() {
    qstring home;
    auto found_home = qgetenv("HOME", &home);
    if (!found_home)
        return fs::path("/tmp/");
    auto p = fs::path(home.c_str());
    p = p / bintag_basedir;
    return p;
}

static fs::path get_tag_dir() {
    return get_config_dir() / "tags";
}

static std::list<json> load_tags() {
    auto tag_dir = get_tag_dir();

    if (!(fs::exists(tag_dir) && fs::is_directory(tag_dir))) {
        msg("BinTag [WARNING]: the tag directory %s does not exist!\n", tag_dir.c_str());
        return std::list<json>();
    }
    msg("BinTag [INFO]: reading tags from %s\n", tag_dir.c_str());

    std::list<json> tags;
    for (auto &p: fs::directory_iterator(tag_dir)) {
        if (!fs::is_regular_file(p))
            continue;
        msg("BinTag [INFO]: loading tag %s\n", p.path().c_str());
        json t;
        try {
            std::ifstream i(p.path());
            i >> t;
            i.close();
            if (t["histogram"].size() != 0)
                tags.push_back(t);
        } catch (json::exception &e) {
            msg("BinTag [WARNING]: could not load tag %s\n", p.path().c_str());
        }
    }

    return tags;
}

/*
 * =====================================================================================
 * functions retrieving information on the loaded binary using the ida api
 * =====================================================================================
 */

static void get_mnemonics(ea_t start_ea, ea_t end_ea, qlist<qstring> *mnemonics) {
    ea_t ea = start_ea;
    do {
        insn_t insn;
        decode_insn(&insn, ea);
        qstring mnem = insn.get_canon_mnem();
        mnemonics->push_back(mnem);
        ea += insn.size;
        if (insn.size == 0)
            break;
    } while(ea < end_ea && ea != BADADDR);
}

static json get_mnem_histogram() {
    json h;
    func_t* fchunk = get_next_fchunk(inf_get_min_ea());
    do {
        qlist<qstring> mnemonics;
        qstring fname;

        ea_t start_ea = fchunk->start_ea;
        ea_t end_ea = fchunk->end_ea;
        if (start_ea == NULL ||
                end_ea == NULL)
            break;

        show_addr(start_ea);
        get_mnemonics(start_ea, end_ea, &mnemonics);

        get_func_name(&fname, start_ea);
        for (auto &mnem : mnemonics)
        {
            if (h[fname.c_str()].find(mnem.c_str()) != h[fname.c_str()].end())
                h[fname.c_str()][mnem.c_str()] = h[fname.c_str()][mnem.c_str()].get<unsigned int>() + 1;
            else
                h[fname.c_str()][mnem.c_str()] = 1u;
        }

        fchunk = get_next_fchunk(end_ea);

        if (user_cancelled())
            break;
    } while(fchunk != NULL);

    return h;
}

// import_enum_cb_t implementation
static int idaapi import_enum_cb(ea_t ea, const char* name, uval_t ordinal, void* param) {
    std::list<std::string> *imports = reinterpret_cast<std::list<std::string> *>(param);
    if (name)
        imports->push_back(name);
    return 1;
}

static std::list<std::string> get_imports() {
    std::list<std::string> imports;
    for (uint i = 0; i<get_import_module_qty(); i++)
        enum_import_names(i, import_enum_cb, &imports);
    return imports;
}

/*
 * =====================================================================================
 * implementation of the distance computation
 * =====================================================================================
 */

inline
static double calculate_euclidean_function_distance(std::vector<double> f0, std::vector<double> f1) {
    // euclid distance of vectors
    double d_f0f1 = 0.0;
    for (int i=0; i<f0.size(); i++) {
        d_f0f1 += pow(f0[i] - f1[i], 2.0);
    }
    return sqrt(d_f0f1);
}

inline
static double calculate_cosine_function_distance(std::vector<double> f0, std::vector<double> f1) {
    // -1 : exactly the opposite
    //  0 : orthogonal
    //  1 : exactly the same
    double a = 0;
    int n = f0.size();
    for (int i=0; i<n; i++) {
        a += f0[i] * f1[i];
    }
    if (a == 0) {
        // exactly the opposite
        return 1.0;
    }

    double b = 0;
    for (int i=0; i<n; i++) {
        b += pow(f0[i], 2.0);
    }
    b = sqrt(b);

    double c = 0;
    for (int i=0; i<n; i++) {
        c += pow(f1[i], 2.0);
    }

    double cos_phi =  a / (b*c);
    return 1.0 - 2.0*acos(cos_phi) / M_PI;
}

static std::vector<std::vector<double> > transpose(std::vector<std::vector<double> > M) {
    unsigned int i = 0;
    std::vector<std::vector<double> > Mt;
    Mt.resize(M[0].size());
    for (auto &r : Mt) {
        r.resize(M.size());
    }
    for (auto &r : M) {
        unsigned int j = 0;
        for (auto &d : r) {
            Mt[j][i] = d;
            j += 1;
        }
        i += 1;
    }
    return Mt;
}

static double calculate_distance(json s0, json s1) {
    // build list with all mnemonics present in both samples
    std::list<std::string> mnemonics;
    for (auto &[f_s0, f_s0_hist] : s0.items()) {
        for (auto &[f_s0_mnem, f_s0_mnem_count] : f_s0_hist.items()) {
            if (std::find(mnemonics.begin(), mnemonics.end(), f_s0_mnem) == mnemonics.end())
                mnemonics.push_back(f_s0_mnem);
        }
    }
    for (auto &[f_s1, f_s1_hist] : s1.items()) {
        for (auto &[f_s1_mnem, f_s1_mnem_count] : f_s1_hist.items()) {
            if (std::find(mnemonics.begin(), mnemonics.end(), f_s1_mnem) == mnemonics.end())
                mnemonics.push_back(f_s1_mnem);
        }
    }
    mnemonics.sort();

    // build function histogram vectors
    std::vector<std::vector<double> > v_s0, v_s1;
    v_s0.resize(s0.size());
    v_s1.resize(s1.size());
    unsigned int i = 0;
    for (auto &[f_s0, f_s0_hist] : s0.items()) {
        for (auto &mnem : mnemonics) {
            if (f_s0_hist.find(mnem) != f_s0_hist.end())
                v_s0[i].push_back(f_s0_hist[mnem]);
            else
                v_s0[i].push_back(0.0);
        }
        i++;
    }
    i = 0;
    for (auto &[f_s1, f_s1_hist] : s1.items()) {
        for (auto &mnem : mnemonics) {
            if (f_s1_hist.find(mnem) != f_s1_hist.end())
                v_s1[i].push_back(f_s1_hist[mnem]);
            else
                v_s1[i].push_back(0.0);
        }
        i++;
    }

    std::vector<std::vector<double> > D;
    D.resize(v_s0.size());
    i = 0;
    for (auto &f_s0 : v_s0) {
        unsigned int j = 0;
        D[i].resize(v_s1.size());
        for (auto &f_s1 : v_s1) {
            double cosine_distance = calculate_cosine_function_distance(f_s0, f_s1);
            double euclidean_distance = calculate_euclidean_function_distance(f_s0, f_s1);
            D[i][j] = (cosine_distance * euclidean_distance);
            j += 1;
        }
        i += 1;
    }

    double dh = 0.0;
    double dv = 0.0;
    for (auto &d_r : D) {
        dh += *std::min_element(d_r.begin(), d_r.end());
    }
    dv = dv / D.size();
    auto Dt = transpose(D);
    for (auto &d_r : Dt) {
        dv += *std::min_element(d_r.begin(), d_r.end());
    }
    dh = dh / Dt.size();

    return (dh > dv) ? dh : dv;
}

/*
 * =====================================================================================
 * code related to the import of BinTags
 * =====================================================================================
 */

static bool skip_tag(json h, json t) {
    bool err = false;
    try {
        // abi checks
        if (inf_is_32bit() != t["arch"]["is_32bit"] ||
                inf_is_64bit() != t["arch"]["is_64bit"]) {
            true;
        }

        // # of functions
        auto s_f = double(h.size());
        auto s_t = double(t["histogram"].size());
        if (h.size() != t["histogram"].size()) {
            auto r = abs(s_f - s_t) / (s_f + s_t);
            if (r > 0.3) {
                return true;
            }
        }
    } catch (json::exception &e) {
        msg("BinTag [WARNING]: broken tag file\n");
        err = true;
    }
    if (err)
        return true;

    return false;
}

/*
 * =====================================================================================
 * feature comparison functions
 * =====================================================================================
 */

static bool same_imports(std::list<std::string> sample_imports) {
    auto imports = get_imports();
    if (sample_imports.size() != imports.size())
        return false;
    imports.sort();
    sample_imports.sort();
    for (int i=0; i<imports.size(); i++) {
        if (imports.back() != sample_imports.back())
            return false;
        imports.pop_back();
        sample_imports.pop_back();
    }
    return true;
}

/*
 * =====================================================================================
 * ui code
 * =====================================================================================
 */

static bool idaapi ct_keyboard(TWidget * /*v*/, int key, int shift, void *ud) {
    if ( shift == 0 )
    {
        bintag_info_t *si = (bintag_info_t *)ud;
        switch ( key )
        {
            case IK_ESCAPE:
                close_widget(si->cv, WCLS_SAVE | WCLS_CLOSE_LATER);
                return true;
        }
    }
    return false;
}

static const custom_viewer_handlers_t handlers(
        ct_keyboard,
        NULL, // popup
        NULL, // mouse_moved
        NULL, // click
        NULL, // dblclick
        NULL,
        NULL, // close
        NULL, // help
        NULL);// adjust_place

/*
 * =====================================================================================
 * BinTag main functions
 * =====================================================================================
 */

static void bintag() {
    if (!auto_is_ok())
        auto_wait();

    TWidget *widget = find_widget("BinTag View");
    if (widget != NULL) {
        destroy_custom_viewer(widget);
        widget = NULL;
    }

    show_wait_box("BinTag computing distances");

    // load tags from tag directory
    auto tags = load_tags();

    // build mnemonics histogram
    auto h = get_mnem_histogram();

    std::vector<std::tuple<std::string, double, std::string, std::list<std::string> > > distances;
    for (auto &tag : tags) {
        if (user_cancelled())
            break;
        if (skip_tag(h, tag)) {
            try {
                msg("BinTag [INFO]: skipping tag %s\n", tag["tag"].get<std::string>().c_str());
            } catch (json::exception &e) {
                msg("BinTag [WARNING]: corrupt tag data\n");
            }
            continue;
        }

        double d = -1;
        std::list<std::string> imports;
        try {
            d = calculate_distance(tag["histogram"], h);
            for (auto &import : tag["imports"]) {
                imports.push_back(import);
            }
            distances.push_back({tag["tag"].get<std::string>(),
                    d,
                    tag["description"].get<std::string>(),
                    imports});
        } catch (json::exception &e) {
            msg("BinTag [WARNING]: corrupt tag data\n");
        }
    }

    auto sortfunction = [](auto const &a, auto const &b) {
        return std::get<1>(a) < std::get<1>(b);
    };
    std::sort(distances.begin(), distances.end(), sortfunction);

    bintag_info_t *si = new bintag_info_t();
    last_si = si;
    for (auto &dist : distances) {
        auto d = std::get<1>(dist);
        if (d < 5.0) {
            std::stringstream ss;
            ss <<
                COLOR_ON << SCOLOR_DNAME <<
                std::get<0>(dist) <<
                COLOR_OFF << SCOLOR_DNAME <<
                COLOR_ON << SCOLOR_NUMBER <<
                " (" << d << ")" <<
                COLOR_OFF << SCOLOR_NUMBER;
            si->sv.push_back(simpleline_t(ss.str().c_str())); // add tag name and distance
            if (same_imports(std::get<3>(dist))) {
                std::stringstream ss;
                ss <<
                    COLOR_ON << SCOLOR_AUTOCMT <<
                    "* imports match" <<
                    COLOR_OFF << SCOLOR_AUTOCMT;
                si->sv.push_back(simpleline_t(ss.str().c_str())); // add tag name and distance
            }
            auto description = std::get<2>(dist);
            std::istringstream lines(description);
            for (std::string line; std::getline(lines, line); ) { // add description line by line
                si->sv.push_back(simpleline_t(line.c_str()));
            }
            si->sv.push_back(simpleline_t("")); // add empty line
            si->sv.push_back(simpleline_t("")); // add empty line
        }
    }
    hide_wait_box();

    simpleline_place_t s1;
    simpleline_place_t s2(si->sv.size()-1);
    si->cv = create_custom_viewer("BinTag View", &s1, &s2, &s1, NULL, &si->sv, &handlers, si);
    display_widget(si->cv, WOPN_DP_TAB|WOPN_RESTORE);

    return;
}

bool idaapi add_tag() {
    qstring tagname = "Tag";
    qstring description;

    constexpr char formdef[] =
        "BUTTON YES Submit\n"
        "BUTTON CANCEL Cancel\n"
        "BUTTON NO NONE\n"
        "Add BinTag\n"
        "<~T~ag:q:1023:50::>\n"
        "\n"
        "<~D~escription:t:1023:50:::>\n"
        "\n";

    textctrl_info_t ti;
    ti.cb = sizeof(textctrl_info_t);
    ti.text = qstring("description for this tag");
    if(!ask_form(formdef, &tagname, &ti))
        return false;

    auto config_dir = get_config_dir();
    if (!fs::exists(config_dir)) {
        fs::create_directory(config_dir);
    }
    if (!fs::is_directory(config_dir)) {
        msg("BinTag [ERROR]: %s is not a directory\n", config_dir.c_str());
        return false;
    }
    auto tag_dir = config_dir / "tags";
    if (!fs::exists(tag_dir)) {
        fs::create_directory(tag_dir);
    }
    if (!fs::is_directory(tag_dir)) {
        msg("BinTag [ERROR]: %s is not a directory\n", tag_dir.c_str());
        return false;
    }
    auto tag_file = tag_dir / tagname.c_str();
    if (is_regular_file(tag_file)) {
        // overwrite ?
        if (ask_yn(ASKBTN_NO, "Overwrite tag at %s?", tag_file.c_str()) == ASKBTN_NO)
            return false;
        // delete old tag_file
        fs::remove(tag_file);
    } else if (fs::exists(tag_file)) {
        // something is there but it is not a regular file...
        msg("BinTag [ERROR]: file at %s is not a regular file\n", tag_file.c_str());
        return false;
    }

    // write histogram of currently opened sample to tag file
    auto hist = get_mnem_histogram();
    json tag;
    tag["histogram"] = hist;
    tag["tag"] = tagname.c_str();
    tag["description"] = ti.text.c_str();
    tag["arch"] = json();
    tag["arch"]["is_64bit"] = inf_is_64bit();
    tag["arch"]["is_32bit"] = inf_is_32bit();
    tag["imports"] = get_imports();
    std::ofstream o(tag_file.c_str());
    o << tag << std::endl;
    o.close();

    return true;
}

/*
 * =====================================================================================
 * ida plugin interface implementation
 * =====================================================================================
 */

static ssize_t idaapi idp_callback(void *, int event_id, va_list) {
    if (event_id == processor_t::ev_newfile)
        bintag();
    return 0;
}

int idaapi init(void) {
    if (!is_idaq())
        return PLUGIN_SKIP;

    static const action_desc_t add_tag_desc = ACTION_DESC_LITERAL(
            ADD_TAG_ACTION_NAME,
            ADD_TAG_ACTION_LABEL,
            &add_tag_ah,
            NULL,
            NULL,
            -1);
    if ( !register_action(add_tag_desc)
            || !attach_action_to_menu("Edit", ADD_TAG_ACTION_NAME, SETMENU_APP)) {
        msg("BinTag [ERROR]: failed to register menu item");
        return PLUGIN_SKIP;
    }

    hook_to_notification_point(HT_IDP, idp_callback);
    return PLUGIN_KEEP;
}

void idaapi term(void) {
    unhook_from_notification_point(HT_IDP, idp_callback);
}

bool idaapi run(size_t) {
    bintag();
    return true;
}

/*
 * =====================================================================================
 * export of ida plugin interface implementation
 * =====================================================================================
 */
plugin_t PLUGIN = {
    IDP_INTERFACE_VERSION,
    NULL,                 // plugin flags
    init,                 // initialize
    term,                 // terminate. this pointer may be NULL.
    run,                  // invoke plugin
    comment,              // long comment about the plugin
    help,                 // multiline help about the plugin
    wanted_name,          // the preferred short name of the plugin
    wanted_hotkey,        // the preferred hotkey to run the plugin
};

