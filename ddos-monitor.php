<?php
/*
Plugin Name: DDoS Monitor
Description: Monitors traffic and blocks IPs suspected of DDoS attacks.
Version: 1.3
Author: Muhamad Ghufron
*/

if (!defined('ABSPATH')) {
    exit; // Exit if accessed directly.
}

// List of known search engine bots
$known_bots = [
    'googlebot', 'bingbot', 'slurp', 'duckduckbot', 'baiduspider', 'yandexbot', 'sogou', 'exabot', 'facebot', 'ia_archiver'
];

// Function to log IP addresses
function ddos_monitor_log_ip() {
    global $known_bots;

    $ip = $_SERVER['REMOTE_ADDR'];
    $user_agent = strtolower($_SERVER['HTTP_USER_AGENT']);
    $current_time = current_time('timestamp');

    // Check if the request is from a known bot
    foreach ($known_bots as $bot) {
        if (strpos($user_agent, $bot) !== false) {
            return; // Skip logging for known bots
        }
    }
    
    // Get the current log from the database
    $ip_log = get_option('ddos_monitor_ip_log', []);
    
    // Clean up old log entries
    foreach ($ip_log as $logged_ip => $log_data) {
        if ($log_data['last_access'] < $current_time - 3600) { // 1 hour
            unset($ip_log[$logged_ip]);
        }
    }

    // Log the current request
    if (!isset($ip_log[$ip])) {
        $ip_log[$ip] = [
            'count' => 0,
            'last_access' => $current_time,
            'user_agent' => $user_agent,
        ];
    }
    
    $ip_log[$ip]['count']++;
    $ip_log[$ip]['last_access'] = $current_time;
    $ip_log[$ip]['user_agent'] = $user_agent;

    // Update the log in the database
    update_option('ddos_monitor_ip_log', $ip_log);

    // Check for potential DDoS attack
    if ($ip_log[$ip]['count'] > 100) { // Threshold for DDoS detection
        ddos_monitor_block_ip($ip);
    }
}
add_action('init', 'ddos_monitor_log_ip');

// Function to block IP addresses
function ddos_monitor_block_ip($ip) {
    $blocked_ips = get_option('ddos_monitor_blocked_ips', []);
    if (!in_array($ip, $blocked_ips)) {
        $blocked_ips[] = $ip;
        update_option('ddos_monitor_blocked_ips', $blocked_ips);
    }

    // Deny access to blocked IPs
    if (in_array($_SERVER['REMOTE_ADDR'], $blocked_ips)) {
        header('HTTP/1.0 403 Forbidden');
        exit('Your IP has been blocked due to suspected DDoS attack.');
    }
}
add_action('init', 'ddos_monitor_block_ip');

// Add admin menu
function ddos_monitor_admin_menu() {
    add_menu_page('DDoS Monitor', 'DDoS Monitor', 'manage_options', 'ddos-monitor', 'ddos_monitor_admin_page', 'dashicons-shield', 100);
}
add_action('admin_menu', 'ddos_monitor_admin_menu');

// Include WP_List_Table if not already included
if (!class_exists('WP_List_Table')) {
    require_once ABSPATH . 'wp-admin/includes/class-wp-list-table.php';
}

// Extend WP_List_Table to create a custom table
class DDoS_Monitor_Table extends WP_List_Table {
      public function prepare_items() {
        $per_page = 20;
        $columns = $this->get_columns();
        $hidden = [];
        $sortable = $this->get_sortable_columns();

        $this->_column_headers = [$columns, $hidden, $sortable];

        // Get the current page number
        $current_page = $this->get_pagenum();

        // Retrieve data from database
        $ip_log = get_option('ddos_monitor_ip_log', []);

        // Prepare the data with IP as a key
        $data = [];
        foreach ($ip_log as $ip => $log_data) {
            $data[] = array_merge($log_data, ['ip' => $ip]);
        }

        // Sort data
        usort($data, function($a, $b) {
            return $b['last_access'] - $a['last_access'];
        });

        // Pagination logic
        $total_items = count($data);
        $data = array_slice($data, (($current_page - 1) * $per_page), $per_page);

        // Set the items
        $this->items = $data;

        // Set pagination arguments
        $this->set_pagination_args([
            'total_items' => $total_items,
            'per_page' => $per_page,
            'total_pages' => ceil($total_items / $per_page),
        ]);
    }


    public function get_columns() {
        $columns = [
            'ip_address'   => 'IP Address',
            'count'        => 'Request Count',
            'last_access'  => 'Last Access',
            'user_agent'   => 'User Agent'
        ];
        return $columns;
    }

    public function column_default($item, $column_name) {
        switch ($column_name) {
            case 'ip_address':
                return esc_html($item['ip']);
            case 'count':
                return esc_html($item['count']);
            case 'last_access':
                return esc_html(date('Y-m-d H:i:s', $item['last_access']));
            case 'user_agent':
                return esc_html($item['user_agent']);
            default:
                return print_r($item, true); // For debugging purposes
        }
    }
}

// Function to clear all logged IPs
function ddos_monitor_clear_log() {
    update_option('ddos_monitor_ip_log', []);
    echo '<div class="updated"><p>All logged IPs have been cleared.</p></div>';
}


// Admin page
function ddos_monitor_admin_page() {
    if (!current_user_can('manage_options')) {
        return;
    }

    // Handle unblock IP action
    if (isset($_POST['unblock_ip'])) {
        $ip_to_unblock = sanitize_text_field($_POST['unblock_ip']);
        ddos_monitor_unblock_ip($ip_to_unblock);
        echo '<div class="updated"><p>IP ' . esc_html($ip_to_unblock) . ' has been unblocked.</p></div>';
    }

    // Handle clear log action
    if (isset($_POST['clear_log'])) {
        ddos_monitor_clear_log();
    }

    echo '<div class="wrap">';
    echo '<h1>DDoS Monitor</h1>';
    
    // Add the clear log button
    echo '<form method="post">';
    echo '<input type="hidden" name="clear_log" value="1">';
    echo '<input type="submit" class="button button-secondary" value="Clear All Logged IPs">';
    echo '</form>';
    
    $ddos_monitor_table = new DDoS_Monitor_Table();
    $ddos_monitor_table->prepare_items();
    echo '<h2>Logged IPs</h2>';
    $ddos_monitor_table->display();

    $blocked_ips = get_option('ddos_monitor_blocked_ips', []);

    echo '<h2>Blocked IPs</h2>';
    if (!empty($blocked_ips)) {
        echo '<table class="widefat"><thead><tr><th>IP Address</th><th>Action</th></tr></thead><tbody>';
        foreach ($blocked_ips as $ip) {
            echo '<tr>';
            echo '<td>' . esc_html($ip) . '</td>';
            echo '<td><form method="post"><input type="hidden" name="unblock_ip" value="' . esc_attr($ip) . '"><input type="submit" class="button button-secondary" value="Unblock"></form></td>';
            echo '</tr>';
        }
        echo '</tbody></table>';
    } else {
        echo '<p>No IPs blocked.</p>';
    }

    echo '</div>';
}


// Function to unblock IP addresses
function ddos_monitor_unblock_ip($ip) {
    $blocked_ips = get_option('ddos_monitor_blocked_ips', []);
    $blocked_ips = array_diff($blocked_ips, [$ip]);
    update_option('ddos_monitor_blocked_ips', $blocked_ips);
}
