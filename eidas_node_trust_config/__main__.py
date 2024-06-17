from collections import defaultdict
from itertools import repeat
import argparse
from eidas_node_trust_config import configuration, utils

CONFIGURATION_SCHEMA_ID = "urn:pypi:eidas_node_trust_config:schemas:configuration"
SCHEMA_DEREFERENCE_PROC_SUFFIX = "::dereference"

class AppendBooleanOptionalAction(argparse.BooleanOptionalAction):
    def __call__(self, parser, namespace, values, option_string=None):
        current_values = getattr(namespace, self.dest, [])
        super().__call__(parser, namespace, values, option_string)
        bool_val = getattr(namespace, self.dest)
        setattr(namespace, self.dest, current_values + [bool_val])

def add_arguments_from_config_schema(parser, config_schema_id):
    def add_argument_for_property(parser, prop, prop_obj, prefix=""):
        choice_to_type_map = {
            str: "string",
            int: "integer",
            float: "number",
            bool: "boolean",
            type(None): "null",
        }
        if not prop_obj.get("argparse", True):
            return
        add_argument_kwargs = {}
        for (k, kwarg) in (repeat('metavar', 2), ('description', 'help')):
            update_kwargs_from_mapping(prop_obj, k, add_argument_kwargs, kwarg)
        add_argument_kwargs["default"] = prop_obj.get("default", argparse.SUPPRESS)
        if prefix:
            prefixed_prop = f"{prefix}_{prop}"
            add_argument_kwargs["action"] = 'append'
            add_argument_kwargs["default"] = []
        else:
            prefixed_prop = prop

        if 'enum' in prop_obj:
            choices = prop_obj["enum"]
            add_argument_kwargs["choices"] = choices
            add_argument_kwargs.pop('metavar', None)
            prop_type = [choice_to_type_map[type(choice)] for choice in choices if type(choice) in choice_to_type_map]
        else:
            prop_type = prop_obj.get("type", [])
            if not isinstance(prop_type, list):
                prop_type = [prop_type]

        if "null" in prop_type or prop_obj.get("default", argparse.SUPPRESS) is None:
            add_argument_kwargs["type"] = lambda val: None if isinstance(val, str) and val.lower() in ("none", "null") else val
        if prop_type == ["integer"]:
            add_argument_kwargs["type"] = int
        elif prop_type == ["number"]:
            add_argument_kwargs["type"] = float
        elif prop_type == ["boolean"]:
            add_argument_kwargs["action"] = \
                AppendBooleanOptionalAction if add_argument_kwargs.get("action") == 'append' else argparse.BooleanOptionalAction

        if any(pt in prop_type for pt in choice_to_type_map.values()) or \
            any(k in prop_obj for k in ("$ref", "allOf", "anyOf", "oneOf")):
            pass # skip to adding the argument
        elif prop_type == ["array"]:
            prop_items = prop_obj.get("items")
            if prop_items.get("type") == "string" or prop_items.get("$ref") is not None:
                add_argument_kwargs["nargs"] = "+"
            elif prop_items.get("type") == "object":
                prop_items_properties = prop_items.get("properties")
                if prop_items_properties:
                    group = parser.add_argument_group(title=prop, description=add_argument_kwargs.get("help"))
                    for nested_prop, nested_prop_obj in prop_items_properties.items():
                        add_argument_for_property(group, nested_prop, nested_prop_obj, prefix=prefixed_prop)
                return
        else:
            return
        parser.add_argument(f"--{prefixed_prop.replace('_', '-')}", **add_argument_kwargs)
        if prefix:
            arg_groups[prefix].append(prefixed_prop)
            arg_groups_arg_defaults[prefix][prefixed_prop] = prop_obj.get("default", argparse.SUPPRESS)

    config_schema = utils.get_json_schema_from_registry(config_schema_id)
    config_root_properties = config_schema["properties"]

    arg_groups = defaultdict(list)
    arg_groups_arg_defaults = defaultdict(dict)

    for prop, prop_obj in config_root_properties.items():
        add_argument_for_property(parser, prop, prop_obj)

    return parser, arg_groups, arg_groups_arg_defaults

def config_from_args(parser, args, arg_groups, arg_groups_arg_defaults):
    config = {}
    for group, properties in arg_groups.items():
        num_values_required = max(len(getattr(args, prop)) for prop in properties)
        if num_values_required == 0:
            continue
        for prop in properties:
            if not getattr(args, prop):
                choices = next((action.choices for action in parser._get_optional_actions() if action.dest == prop), [])
                if arg_groups_arg_defaults[group][prop] != argparse.SUPPRESS:
                    prop_default = arg_groups_arg_defaults[group][prop]
                elif choices:
                    prop_default = choices[0]
                else:
                    raise ValueError(f"Missing values for {prop}")
                setattr(args, prop, [prop_default] * num_values_required)
            elif len(getattr(args, prop)) != num_values_required:
                raise ValueError(f"Missing or extra values for {prop}")
        group_dicts = []
        for i in range(num_values_required):
            group_dict = {}
            for prop in properties:
                prop_name = prop.removeprefix(f"{group}_")
                arg_value = getattr(args, prop)[i]
                group_dict[prop_name] = arg_value
            group_dicts.append(group_dict)
        config[group] = group_dicts
    for arg in vars(args):
        if not any(arg in props for props in arg_groups.values()):
            config[arg] = getattr(args, arg)
    return config

def update_kwargs_from_mapping(source_mapping, source_param, dest_mapping, dest_param, cb=None):
    if source_param not in source_mapping:
        return
    param_value = source_mapping[source_param]
    if callable(cb):
        param_value = cb(param_value)
    dest_mapping[dest_param] = param_value

def run_config_tasks(config):
    enta_kwargs = {}
    for k in ('node_country_code', 'api_countries', 'manual_countries', 'metadata_service_lists'):
        update_kwargs_from_mapping(config, k, enta_kwargs, k)
    edfa_kwargs = {}
    for k in ('only_active', 'filter_expired'):
        update_kwargs_from_mapping(config, k, edfa_kwargs, k)
    enta = configuration.EidasNodeTrustAggregator(**enta_kwargs, **edfa_kwargs)

    for tasks_section in ('eidas_node_props', 'eidas_node_mds_certs'):
        for task in config.get(tasks_section, []):
            data_kwargs = {}
            update_kwargs_from_mapping(config, 'environment', data_kwargs, 'environment', lambda v: configuration.EidasNodeTrustAggregator.Environment(v))
            update_kwargs_from_mapping(task, 'component', data_kwargs, 'component', lambda n: configuration.EidasNodeTrustAggregator.Component[n] if n is not None else n)
            if tasks_section == 'eidas_node_props':
                for src_mapping, src_param, dst_param in (
                    (config, *repeat('only_active', 2)),
                    (task, *repeat('detailed_proxyservice', 2)),
                    (config, 'single_proxyservice_endpoint_per_country', 'require_single_proxyservice_endpoint')):
                    update_kwargs_from_mapping(src_mapping, src_param, data_kwargs, dst_param)
                # print(f"would run get_metadata_endpoints with {data_kwargs}")
                # continue
                data = enta.get_metadata_endpoints(**data_kwargs)
                template = task.get('template')
                configuration.render_and_validate_template(template, data)
            elif tasks_section == 'eidas_node_mds_certs':
                # print(f"would run get_signing_certificates with {data_kwargs}, {edfa_kwargs}")
                # continue
                fp_cert_map, fp_cc_map = enta.get_signing_certificates(**data_kwargs, **edfa_kwargs)
                output_dir = task.get('dir')
                if not task.get('cc_links'):
                    fp_cc_map = None
                configuration.write_certs_to_dir(output_dir, fp_cert_map, file_extension='pem', fp_cc_mapping=fp_cc_map)

def main():
    # import json
    parser = argparse.ArgumentParser(prog=__package__, description='eIDAS node trust configuration')
    parser.add_argument('--config', metavar='CONFIG.yml', help='Path to the YAML configuration file')
    parser.add_argument('--write-config-schema', metavar='SCHEMA.json', help='Path to the file where the configuration JSON schema (self-contained, after dereferencing) should be written')
    parser, arg_groups, arg_groups_arg_defaults = add_arguments_from_config_schema(parser, f"{CONFIGURATION_SCHEMA_ID}{SCHEMA_DEREFERENCE_PROC_SUFFIX}")
    args = parser.parse_args()
    config_args = config_from_args(parser, args, arg_groups, arg_groups_arg_defaults)
    # print(json.dumps(config_args, indent=2))
    config_schema_file = config_args.pop('write_config_schema')
    if config_schema_file:
        utils.write_json_schema_to_file(f"{CONFIGURATION_SCHEMA_ID}{SCHEMA_DEREFERENCE_PROC_SUFFIX}", config_schema_file)
    config_file = config_args.pop('config')
    config = utils.load_config_file_and_merge_with_args(config_file, config_args)
    if not config:
        return
    # print(json.dumps(config, indent=2))
    utils.validate_data_with_json_schema(config, CONFIGURATION_SCHEMA_ID)
    run_config_tasks(config)

if __name__ == '__main__':
    main()
