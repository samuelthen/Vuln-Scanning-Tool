import yaml

def convert_properties_to_dict(properties_file):
    config_dict = {}
    with open(properties_file, 'r') as file:
        for line in file:
            line = line.strip()
            if line and not line.startswith('#'):
                key, value = line.split('=', 1)
                key = key.strip()
                value = value.strip()
                keys = key.split('.')
                d = config_dict
                for part in keys[:-1]:
                    if part not in d:
                        d[part] = {}
                    elif isinstance(d[part], str):
                        d[part] = {'value': d[part]}  # Convert to dict if it's a string
                    d = d[part]
                if keys[-1] in d and isinstance(d[keys[-1]], dict):
                    d[keys[-1]]['value'] = value
                else:
                    d[keys[-1]] = value
    return config_dict

def write_dict_to_yaml(config_dict, yaml_file):
    with open(yaml_file, 'w') as file:
        yaml.dump(config_dict, file, default_flow_style=False)

# Convert the .properties file to a dictionary
properties_file = 'Messages.properties'
config_dict = convert_properties_to_dict(properties_file)

# Write the dictionary to a YAML file
yaml_file = 'messages.yaml'
write_dict_to_yaml(config_dict, yaml_file)
